# DNSSEC setup for dnsseed

##### Table of Contents  
[Requirements](#Requirements)  
[Software needed](#Software)  
[Setup](#Setup)  
[Testing](#Testing)  
[Example](#Example)  
[Improvements](#Improvements)  
[Links](#Links)  


<a name="Requirements"/>

## Recommendation
* run only this service on the host (security precaution)

<a name="Software"/>

## Software needed

* Debian GNU/Linux 10
* tor
* bind9
* dig (debian package bind9-dnsutils)
* nsupdate (debian package bind9-dnsutils)
* bitcoin-seeder
* ufw
* bash

```
apt update
apt install bind9 bind9-dnsutils bind9utils ufw tor
```

<a name="Setup"/>

## Setup

### ufw
Configure and enable firewall
```
ufw allow 22/tcp
ufw allow 53/udp
ufw allow 53/tcp
ufw enable
ufw status
```

### Configuring Bind9
Replace `example.com` with your domain.

* add or change in /etc/bind/named.conf.options 
```
        querylog no;
	allow-transfer { none; };
	dnssec-enable yes;
```

* add to /etc/bind/named.conf.local 
```
zone "dnsseed.example.com" {
      type master;
      file "/var/lib/bind/db.dnsseed.example.com";
      key-directory "/var/lib/bind";
      allow-update {localhost;};
      auto-dnssec maintain;
      inline-signing yes;
};
```

* Generate new file /var/lib/bind/db.example.com
```
$ORIGIN .
$TTL 3600       ; 1 hour
dnsseed.example.com.        IN SOA  dnsseed-host.example.com. contact-email.example.com. (
                                2000000001 ; serial
                                3600       ; refresh (1 hour)
                                600        ; retry (10 minutes)
                                86400      ; expire (1 day)
                                600        ; minimum (10 minutes)
                                )
                        NS      dnsseed-host.example.com.
dummy                   A       127.0.0.1
```

* Check config
```
named-checkconf
named-checkzone dnsseed.example.com /var/lib/bind/db.dnsseed.example.com
```

* Restart Bind9
`service bind9 restart`

* Generate DNSSEC keys
```
cd /var/lib/bind
dnssec-keygen -r /dev/urandom -a ECDSAP256SHA256 dnsseed.example.com`
dnssec-keygen -r /dev/urandom -a ECDSAP256SHA256 -b 2048 -fKSK -n ZONE dnsseed.example.com
chown bind: Kdnsseed.example.com*.key
```

* Add keys to zone file
```
cd /var/lib/bind
for key in Kdnsseed.example.com*.key
do
echo "\$INCLUDE $key">> db.example.com
done
```

* Sign zone
```
dnssec-signzone -A -3 $(head -c 1000 /dev/random | sha1sum | cut -b 1-16) -N INCREMENT -o example.com -t db.example.com
```

* Restart Bind9
`service bind9 restart`

* after the restart you will have a file /var/lib/bind/dsset-dnsseed.example.com.
This file contains the DS records that need to be entered in the parent dns zone or in your domain registrar’s control panel.


### Building bitcoin-seeder (should be non root)

* Install requirements
```
sudo apt-get install build-essential libboost-all-dev libssl-dev
```

* Download
```
git pull https://github.com/sipa/bitcoin-seeder.git
```

* Compile
```
make
```

* Start
```
./dnsseed -p5353 -h dnsseed.example.com -n dnsseed-host.example.com -m someting.example.com -o 127.0.0.1:9050 
```

**TODO** systemd service

### Cron script to fetch dns records from bitcoin-seeder

* Download the file 

[/etc/cron.hourly/dnsupdate](contrib/dnsupdate)

* Put it in /etc/cron.hourly/

* Change following line

`ZONE=dnsseed.example.com`

* Make it executable
`chmod +x /etc/cron.daily/dnsupdate`

<a name="Testing"/>

## Testing

* Checking if RRSIG record is present 
```
dig A dnsseed.emzy.de @8.8.8.8 +noadditional +dnssec +multiline
dig AAAA dnsseed.emzy.de @8.8.8.8 +noadditional +dnssec +multiline
dig A x49.dnsseed.emzy.de. +dnssec @8.8.8.8 +dnssec +multiline
dig AAAA x49.dnsseed.emzy.de. +dnssec @8.8.8.8 +dnssec +multiline
```

* Check if all looks good on
https://dnsviz.net/d/dnsseed.emzy.de/dnssec/

* Check syslog that nsupdate is working
/var/log/syslog should have many `updating zone` entries and a `zone ... (signed)` entry every hour.
```
...named[99]: client @0x7fd78048c650 127.0.0.1#41161: updating zone 'dnsseed.emzy.de/IN': adding an RR at 'x40c.dnss
eed.emzy.de' A 134.209.232.105
...named[99]: client @0x7fd7800b8520 127.0.0.1#58337: updating zone 'dnsseed.example.com/IN': adding an RR at 'x448.dnsseed.example.com' AAAA 2600:1f16:625:e00:aefd:9cc7:d3:6e86
[...]
...named[99]: zone dnsseed.emzy.de/IN (signed): serial 2000002744 (unsigned 2000002740)
[...]
```

* * *
<a name="Example"/>

## Example (Debian 10)

### bitcoin-seeder

* Should look like this
```
user@dnsseed:~/bitcoin-seeder$ ./dnsseed -p5353 -h dnsseed.example.com -n dnsseed-host.example.com -m someting.example.com -o 127.0.0.1:9050
Supporting whitelisted filters: 0x1,0x5,0x9,0xd,0x49,0x400,0x404,0x408,0x40c,0x448
Using Tor proxy at 127.0.0.1:9050
Loading dnsseed.dat...done
Starting 4 DNS threads for dnsseed.example.com on dnsseed-host.example.com (port 5353).......done
Starting seeder...done
[20-09-18 13:02:55] 5733/36914 available (34970 tried in 1332s, 408 new, 1536 active), 55236 banned; 112 DNS requests, 44 db queries
```

### Bind9 full config files 

* /etc/bind/named.conf.options
```
options {
        directory "/var/cache/bind";

        // If there is a firewall between you and nameservers you want
        // to talk to, you may need to fix the firewall to allow multiple
        // ports to talk.  See http://www.kb.cert.org/vuls/id/800113

        // If your ISP provided one or more IP addresses for stable 
        // nameservers, you probably want to use them as forwarders.  
        // Uncomment the following block, and insert the addresses replacing 
        // the all-0's placeholder.

        // forwarders {
        //      0.0.0.0;
        // };

        //========================================================================
        // If BIND logs error messages about the root key being expired,
        // you will need to update your keys.  See https://www.isc.org/bind-keys
        //========================================================================
        dnssec-validation auto;

        listen-on-v6 { any; };
       // hide version number from clients for security reasons.
        version "not currently available";

        // disable recursion on authoritative DNS server.
        recursion no;
       
        // disable the query log
        querylog no;
       
        // disallow zone transfer
        allow-transfer { none; };

        dnssec-enable yes;
};
```

* /etc/bind/named.conf.local
```
//
// Do any local configuration here
//

// Consider adding the 1918 zones here, if they are not used in your
// organization
//include "/etc/bind/zones.rfc1918";

zone "dnsseed.emzy.de" {
      type master;
      file "/var/lib/bind/db.dnsseed.emzy.de";
      key-directory "/var/lib/bind";
      allow-update {localhost;};
      auto-dnssec maintain;
      inline-signing yes;
};
```

* /var/lib/bind/db.example.com
```
$ORIGIN .
$TTL 3600       ; 1 hour
dnsseed.example.com.        IN SOA  dnsseed-host.example.com. contact-email.example.com. (
                                2000000001 ; serial
                                3600       ; refresh (1 hour)
                                600        ; retry (10 minutes)
                                86400      ; expire (1 day)
                                600        ; minimum (10 minutes)
                                )
                        NS      dnsseed-host.example.com.
dummy                   A       127.0.0.1
dnsseed.example.com. IN DNSKEY 257 3 13 euXp/lPIx...xuSVYZ clx...xM==
dnsseed.example.com. IN DNSKEY 256 3 13 6CNJQx...xykHv XKx...xg==
```


<a name="Improvements"/>

## Possible improvements
* enable key only authentication on ssh
* use different SSH port (don't forget to add to ufw)
* non root cron job and key for the nsupdate authentication

<a name="Links"/>

## Links
* https://www.digitalocean.com/community/tutorials/how-to-setup-dnssec-on-an-authoritative-bind-dns-server--2
