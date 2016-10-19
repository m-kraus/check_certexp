#!/usr/bin/env perl

# Check certificate expiry.
#
# Copyright (c) 2016 Michael Kraus <Michael.Kraus@consol.de>.
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.

##############################################################################
#
# basic settings
#
##############################################################################

use warnings;
use strict;
use IO::Socket;
use Getopt::Long;
use Net::SSLeay;
use Date::Manip;

use vars qw($opt_H $opt_c $opt_w $opt_h $opt_i $opt_p $opt_t $opt_d $opt_v );

my %ERRORS=('OK'=>0,'WARNING'=>1,'CRITICAL'=>2,'UNKNOWN'=>3);

sub expiry_date ($$$$);
sub get_cert_details ($);
sub verbose ();
sub die_crit ($);
sub die_warn ($);
sub die_ok ($);
sub die_unknown ($);
sub print_usage ();
sub print_help ();
my $suffix = '';

my $PROGNAME = 'check_certexp.pl';

my $CRIT = 28;
my $TIMEOUT = 15;

$SIG{ALRM} = sub { die_unknown("Timeout of $TIMEOUT seconds reached."); };
$ENV{PATH} = '';
$ENV{ENV} = '';
$ENV{TZ} = 'CET';



##############################################################################
#
# parse options
#
##############################################################################

Getopt::Long::Configure('bundling');
if (!GetOptions('h|help'	=> \$opt_h,
                'H|hostname=s'	=> \$opt_H,
                'c|critical=i'	=> \$opt_c,
                'w|warning=i'	=> \$opt_w,
                'p|proxy=s'	=> \$opt_p,
                'i|issuer=s'	=> \$opt_i,
                'd|debug'	=> \$opt_d,
                'v|verbose+'	=> \$opt_v,
                't|timeout=i'	=> \$opt_t,)) {
	print "Error processing command line options\n";
	print_usage();
	exit $ERRORS{UNKNOWN};
}

# help
if ($opt_h) {
	print_help();
	exit $ERRORS{OK};
}

# debug
my $debug = 0;
if ($opt_d) {
	$debug = 1;
}

# verbose
my $verbose = 0;
if ($opt_v) {
	$verbose = $opt_v;
}

# host:port / proxy:port
unless ($opt_H) {
	print "No target host specified\n";
	print_usage();
	exit $ERRORS{UNKNOWN};
}
my ($host, $port, $dhost, $dport, $url);
if ($opt_p) {
	($host, $port) = split(/:/, $opt_p);
	($dhost, $dport) = split(/:/, $opt_H);
	$url = $dhost;
	
} else {
	($host, $port) = split(/:/, $opt_H);
	$dhost = 'no';
	$url = $host;
}
unless ($port) { $port = 443; }
unless ($dport) { $dport = 443; }


# thresholds
my $critical = $opt_c ? $opt_c : $CRIT;
my $warning = $opt_w ? $opt_w : $critical;
if ($warning < $critical) {
	print "WARNING threshold exceeds CRITICAL threshold\n";
	print_usage();
	exit $ERRORS{UNKNOWN};
}

# timeout
my $timeout = $opt_t ? $opt_t : $TIMEOUT;
alarm($timeout);

# issuers
my @issuers = split(/:/, $opt_i) if $opt_i;



##############################################################################
#
# main
#
##############################################################################

# get certificate details
my ($notafter_days, $notafter, $notbefore_days, $notbefore, $subject, $issuer) = expiry_date($host, $port, $dhost, $dport);

# verify subject
print "DEBUG Verify $url with subject [ ",$subject," ]:\n" if $debug;
my $subject_cn = $subject;
$subject_cn=~ s/\/.*CN=([^\/]+).*/$1/;
print "DEBUG Issuer (CN): ",$subject_cn,"\n" if $debug;
die_crit("Subject CN '$subject_cn' does not match: $url") if not $subject_cn =~ /$url/;

# verify issuer
my $issuer_cn = $issuer;
$issuer_cn =~ s/\/.*CN=([^\/]+).*/$1/;
print "DEBUG Issuer (CN): ",$issuer_cn,"\n" if $debug;
if (@issuers) {
	die_crit("Issuer CN '$issuer_cn' does not match: " . join(':', @issuers)) if not grep($issuer_cn eq $_, @issuers);
	$suffix = " (Issuer: $issuer)";
}

# not yet valid
if ($notbefore_days > 0) {
	die_crit("Certificate will be valid in $notbefore_days $suffix");
}

# is expired	
if ($notafter_days < 0) {
    $notafter_days =~ s/^-//;
    die_crit("Certificate expired $notafter_days ago $suffix");
}

# verify against thresholds
die_crit("Certificate expires in $notafter_days days $suffix") if $notafter_days < $critical;
die_warn("Certificate expires in $notafter_days days $suffix") if $notafter_days < $warning;
die_ok("Certificate expires in $notafter_days days $suffix");



##############################################################################
#
# subs
#
##############################################################################

sub expiry_date ($$$$) {
	my ($host, $port, $dhost, $dport) = @_;
	my ($buffer, $iaddr, $paddr, $ctx, $ssl, $crt, $end, $str);
	
	print "DEBUG Connect to host: ",$host,":",$port,"\n" if $debug;
	
	# connect
	$| = 1;
	my $sock = new IO::Socket::INET (
		PeerAddr	=> $host,
		PeerPort	=> $port,
		Proto		=> 'tcp',
	) || die_unknown("Error connecting to $host: $!");
	
	# connect with proxy
	unless ( $dhost eq 'no' ) {
		print "DEBUG Connect via proxy to destination: ",$dhost,":",$dport,"\n" if $debug;
		# send a "CONNECT" command to proxy
		print $sock "CONNECT $dhost:$dport HTTP/1.0\r\n\r\n";
		
		# get HTTP status code, bail out unless 2xx
		my $recv_line = <$sock>;
		my ($status) = (split(/\s+/,$recv_line))[1];
		die_unknown("Received a bad status code \"$status\" from proxy server.") if ( int($status/100) != 2 );
    
		# skip through remaining part of HTTP header (until blank line)
		1 until ( <$sock> =~ /^[\r\n]+$/ );
	}
	
	# initialize SSL
	Net::SSLeay::load_error_strings();
	Net::SSLeay::SSLeay_add_ssl_algorithms();
	Net::SSLeay::randomize();
	$ctx = Net::SSLeay::CTX_new();
	my $mode = &Net::SSLeay::VERIFY_NONE;
	Net::SSLeay::CTX_set_verify($ctx, $mode);
	$ssl = Net::SSLeay::new($ctx);
	Net::SSLeay::set_fd($ssl, fileno($sock));
	Net::SSLeay::connect($ssl);
	# DO NOT DIE HERE IF CONNECTION FAILS - WE CAN GET SERVER CERTIFICATE EVEN WITHOUT SUCCESSFUL CONNECTION THEN
    
	# get certificate
	$crt = Net::SSLeay::get_peer_certificate($ssl)
		|| die_unknown(Net::SSLeay::print_errs('Cannot get peer certificate') or 'Cannot get peer certificate');
	
	# get dates
	my $tmp;
	my $notafter = Net::SSLeay::P_ASN1_UTCTIME_put2string(Net::SSLeay::X509_get_notAfter($crt));
	print "DEBUG NotAfter: ",$notafter,"\n" if $debug;

	$tmp = $notafter;
	$tmp =~ s/ GMT//;
	my $notafter_days = int((&UnixDate(&ParseDate($tmp), '%s') - time) / 86400);
	print "DEBUG NotAfter (days): ",$notafter_days,"\n" if $debug;

	my $notbefore = Net::SSLeay::P_ASN1_UTCTIME_put2string(Net::SSLeay::X509_get_notBefore($crt));
	print "DEBUG NotBefore: ",$notbefore,"\n" if $debug;

	$tmp = $notbefore;
	$tmp =~ s/ GMT//;
	my $notbefore_days = int((&UnixDate(&ParseDate($tmp), '%s') - time) / 86400);
	print "DEBUG NotBefore (days): ",$notbefore_days,"\n" if $debug;
	
	# get subject
	my $subject = Net::SSLeay::X509_NAME_oneline(Net::SSLeay::X509_get_subject_name($crt));
	print "DEBUG Subject: ",$subject,"\n" if $debug;
	
	# get issuer
	my $issuer = Net::SSLeay::X509_NAME_oneline(Net::SSLeay::X509_get_issuer_name($crt));
	print "DEBUG Issuer: ",$issuer,"\n" if $debug;

	# cleanup
	Net::SSLeay::free($ssl);
	Net::SSLeay::CTX_free($ctx);
	$sock->close();
	  
	return ("$notafter_days", "$notafter", "$notbefore_days", "$notbefore", "$subject", "$issuer");
}

sub verbose () {
	if ($verbose == 2) {
		printf "Subject: %s\n",$subject if $subject;
		printf "Issuer: %s\n",$issuer if $issuer;
		printf "NotAfter: %s\n",$notafter if $notafter;
		printf "NotBefore: %s\n",$notbefore if $notbefore;
	}
	if ($verbose == 1) {
		printf "Subject CN: %s\n",$subject_cn if $subject_cn;
		printf "Issuer CN: %s\n",$issuer_cn if $issuer_cn;
		printf "NotAfter: %s\n",$notafter if $notafter;
		printf "NotBefore: %s\n",$notbefore if $notbefore;
	}
}
	

sub die_unknown ($) {
	printf "UNKNOWN: %s\n", shift;
	exit $ERRORS{UNKNOWN};
}

sub die_warn ($) {
	printf "WARNING: %s\n", shift;
	verbose() if $verbose;
	exit $ERRORS{WARNING};
}

sub die_crit ($) {
	printf "CRITICAL: %s\n", shift;
	verbose() if $verbose;
	exit $ERRORS{CRITICAL};
}

sub die_ok ($) {
	printf "OK: %s\n", shift;
	verbose() if $verbose;
	exit $ERRORS{OK};
}

sub print_usage () {
	print "Usage: $PROGNAME -H host [-p proxy] [-i issuer] [-w warn]\n" .
	      "       [-c crit] [-t timeout] [-d] [-v]\n";
}

sub print_help () {
	print "Check certificate expiry date.\n\n";
	print_usage();
	print <<EOF;

 -H, --hostname=ADDRESS[:PORT]
    Host name or IP address, port defaults to 443
 -p, --proxy=ADDRESS[:PORT]
    Proxy name or IP address, port defaults to 443
 -i, --issuer=NAME:NAME
    Certificate issuer name(s)
 -w, --warning=INTEGER
    WARNING if less than specified number of days until expiry (default: $CRIT)
 -c, --critical=INTEGER
    CRITICAL if less than specified number of days until expiry (default: $CRIT)
 -t, --timeout=INTEGER
    Seconds before connection times out (default: $TIMEOUT)
 -d
    Enable debug output
 -v
    Enable verbose output, use multiple for different views

EOF
}
