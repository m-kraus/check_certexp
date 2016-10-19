# check_certexp

Check validity of certificates reachable via HTTP(S)

## Prerequisites

Perl with Net/SSLeay and Date/Manip. For example on Centos7:

```
yum install perl-Net-SSLeay perl-Date-Manip
```

## Usage

```
[root@app1 vagrant]# ./check_certexp.pl -h
Check certificate expiry date.

Usage: check_certexp.pl -H host [-p proxy] [-i issuer] [-w warn]
       [-c crit] [-t timeout] [-d] [-v]

 -H, --hostname=ADDRESS[:PORT]
    Host name or IP address, port defaults to 443
 -p, --proxy=ADDRESS[:PORT]
    Proxy name or IP address, port defaults to 443
 -i, --issuer=NAME:NAME
    Certificate issuer name(s)
 -w, --warning=INTEGER
    WARNING if less than specified number of days until expiry (default: 28)
 -c, --critical=INTEGER
    CRITICAL if less than specified number of days until expiry (default: 28)
 -t, --timeout=INTEGER
    Seconds before connection times out (default: 15)
 -d
    Enable debug output
 -v
    Enable verbose output, use multiple for different views
```
