# DNSSEC setup for dnsseed

The built-in DNS server of bitcoin-seeder does not support DNSSEC. Instead,
bitcoin-seeder can periodically export a zone file with the good nodes it
found, which BIND then signs and serves.

This guide is for a new installation on Debian GNU/Linux 13 (trixie), with
BIND 9.20. bitcoin-seeder runs as an unprivileged user, without its own DNS
server, and writes the zone file every 2 minutes; BIND signs the zone
automatically.

- [Requirements](#requirements)
- [Install software](#install-software)
- [Configure BIND](#configure-bind)
- [Build and start bitcoin-seeder](#build-and-start-bitcoin-seeder)
- [Publish the delegation and DS record](#publish-the-delegation-and-ds-record)
- [Testing](#testing)
- [Links](#links)

## Requirements

Use a dedicated host where practical (a security recommendation). You need
control of the parent DNS zone to publish the seed's NS and DS records.

Replace these example names consistently throughout the configuration:

- `dnsseed.example.com`: the seed zone.
- `dnsseed-host.example.com`: the authoritative nameserver's hostname.
- `contact-email.example.com`: the SOA contact, representing
  `contact-email@example.com`.
- `seeder`: the ordinary user that builds and runs bitcoin-seeder.

Create an A record (and an AAAA record if IPv6 is available) for
`dnsseed-host.example.com` in the **parent** zone, pointing to this machine's
public address. This hostname is outside `dnsseed.example.com`, so its
address belongs in the parent zone, not in the seed zone.

Run the installation and BIND configuration commands below as root. Tor is
not needed for this setup.

## Install software

```sh
apt update
apt install bind9 bind9-dnsutils bind9-utils
```

Allow inbound TCP and UDP port 53 in your firewall. If you use UFW, allow
your actual SSH port before enabling it (the example assumes port 22):

```sh
apt install ufw
ufw allow 22/tcp
ufw allow 53/udp
ufw allow 53/tcp
ufw enable
ufw status
```

## Configure BIND

For a dedicated authoritative server, set these options **inside the existing
`options` block** in `/etc/bind/named.conf.options`, replacing any conflicting
settings:

```conf
recursion no;
allow-query { any; };
allow-transfer { none; };
querylog no;
listen-on { any; };
listen-on-v6 { any; };
```

Add the `seeder` user to the `bind` group, so that it can write the zone file,
and make BIND reload the zone using `rndc` (members of the group can read
`/etc/bind/rndc.key`). Note that this also allows the user to read BIND's
configuration, and to use any other `rndc` command. The change takes effect
the next time the user logs in.

```sh
adduser seeder bind
```

Create a writable directory for the zone, journals and DNSSEC keys, which
bitcoin-seeder (through the `bind` group) writes the zone file to. On Debian,
AppArmor only lets BIND use files in a few places, such as `/var/lib/bind`.

```sh
install -d -o bind -g bind -m 2770 /var/lib/bind/dnsseed.example.com
```

Create an initial `/var/lib/bind/dnsseed.example.com/db.dnsseed.example.com`,
so that BIND can load the zone before the first export:

```dns
$ORIGIN dnsseed.example.com.
$TTL 3600
@ IN SOA dnsseed-host.example.com. contact-email.example.com. (
    1       ; initial serial (bitcoin-seeder's exports increase it)
    3600    ; refresh
    600     ; retry
    86400   ; expire
    600     ; negative cache TTL
)
@ IN NS dnsseed-host.example.com.
```

```sh
chown bind:bind /var/lib/bind/dnsseed.example.com/db.dnsseed.example.com
chmod 0644 /var/lib/bind/dnsseed.example.com/db.dnsseed.example.com
```

Add this zone to `/etc/bind/named.conf.local`:

```conf
zone "dnsseed.example.com" {
    type primary;
    file "/var/lib/bind/dnsseed.example.com/db.dnsseed.example.com";
    key-directory "/var/lib/bind/dnsseed.example.com";
    dnssec-policy default;
    inline-signing yes;
    // Every export replaces most address records. The default journal size
    // limit is too small for that, and would stop the changes from being
    // applied.
    max-journal-size 10m;
};
```

`dnssec-policy default` generates a combined signing key using
ECDSAP256SHA256 and maintains the signatures automatically. With
`inline-signing`, BIND keeps the signed zone separate from the file that
bitcoin-seeder writes, and signs the changes after every reload. Do not
manually generate keys or run `dnssec-signzone` for this setup. Back up the
keys in `/var/lib/bind/dnsseed.example.com`.

For an existing signed zone, retain its key files and published DS record;
plan a policy migration using the BIND documentation linked below rather
than replacing the keys with this fresh-install procedure.

Check the configuration before restarting:

```sh
named-checkconf
named-checkzone dnsseed.example.com /var/lib/bind/dnsseed.example.com/db.dnsseed.example.com
systemctl restart named
systemctl --no-pager status named
journalctl -u named --since '5 minutes ago' --no-pager
```

`named-checkconf` should exit successfully without output, and
`named-checkzone` should report `loaded serial 1` and `OK` for the initial
file. The Debian service is `named.service`.

## Build and start bitcoin-seeder

Install the build dependencies as root:

```sh
apt install build-essential libboost-dev libssl-dev git
```

As the `seeder` user, clone and build the repository, and start dnsseed:

```sh
git clone https://github.com/sipa/bitcoin-seeder.git
cd bitcoin-seeder
make
./dnsseed -h dnsseed.example.com -n dnsseed-host.example.com \
    -m contact-email.example.com --nodns \
    --zonefile /var/lib/bind/dnsseed.example.com/db.dnsseed.example.com \
    --zone-reload "/usr/sbin/rndc reload dnsseed.example.com"
```

Keep the process running (for example under a service manager), always from
the same directory: its database (`dnsseed.dat`) is stored there. `--nodns`
disables the built-in DNS server, so dnsseed needs no root privileges and no
open ports.

Every 2 minutes (see `--zone-interval`), dnsseed replaces the zone file and
runs the reload command. The zone contains the SOA and NS records (from `-h`,
`-n` and `-m`), and up to 25 A and 15 AAAA records (see `--zone-max-ipv4` and
`--zone-max-ipv6`), randomly selected from the good nodes, at the zone apex
and at each filter name that the seeder supports (such as
`x9.dnsseed.example.com`; see its `-w` option).

Answers with that many addresses fit in 512 bytes, the limit for clients that
don't use EDNS when asking their resolver (such as glibc's resolver, unless
`options edns0` is set). Larger answers make those clients retry over TCP,
and their lookup fails entirely if that doesn't work (glibc doesn't use the
truncated answer). Between resolvers and BIND, EDNS is used, and signed
answers fit in the usual 1232-byte buffer up to about 50 A or 30 AAAA
records; that is not the limiting factor.

The TTL of the records is the export interval. Unlike with the built-in DNS
server, which selects addresses for every query, all clients get the same
addresses until the next export; a short interval makes clients of different
resolvers get different addresses over time.

The database needs time to collect reliable nodes. Nothing is exported until
there are good nodes; if there are none (for example when starting with an
empty database), the previous zone file is kept.

For multiple seeds, give each a separate BIND zone, and dnsseed process and
database directory.

## Publish the delegation and DS record

After the first export, wait until BIND serves a DNSKEY and its signature:

```sh
dig @127.0.0.1 dnsseed.example.com DNSKEY +dnssec +norecurse
```

Export the **published** DNSKEY records and derive the SHA-256 DS record:

```sh
dig @127.0.0.1 dnsseed.example.com DNSKEY +noall +answer > /tmp/dnsseed-dnskey.txt
dnssec-dsfromkey -2 -f /tmp/dnsseed-dnskey.txt dnsseed.example.com
```

Expect a DS record containing the key tag, algorithm `13`, digest type `2`,
and a hexadecimal digest.

In the parent zone, delegate `dnsseed.example.com` with an NS record pointing
to `dnsseed-host.example.com`. Once the nameserver is publicly reachable and
serving signatures, publish the derived DS record in that parent zone (or
through the registrar if it manages that delegation). Then let BIND know that
the DS record is published:

```sh
rndc dnssec -checkds published dnsseed.example.com
```

## Testing

Check local authoritative answers over UDP and TCP:

```sh
dig @127.0.0.1 dnsseed.example.com SOA +dnssec +norecurse
dig @127.0.0.1 dnsseed.example.com A +dnssec +norecurse
dig @127.0.0.1 dnsseed.example.com AAAA +dnssec +norecurse
dig @127.0.0.1 x49.dnsseed.example.com A +dnssec +norecurse
dig @127.0.0.1 x49.dnsseed.example.com AAAA +dnssec +norecurse +tcp
```

Expect `status: NOERROR` and the `aa` flag. Nonempty address answers should
include their RRSIG. Empty answers should include signed denial records in
the authority section. An RRSIG proves that signatures are being served;
validation also requires the parent DS chain.

After publishing the NS and DS records and allowing caches to expire, test
with a validating resolver:

```sh
dig @8.8.8.8 dnsseed.example.com A +dnssec
dig @8.8.8.8 x49.dnsseed.example.com AAAA +dnssec
delv dnsseed.example.com A
```

Expect the `ad` flag from the validating resolver and a successful validation
from `delv`. Also inspect your domain at [DNSViz](https://dnsviz.net/).
Use `journalctl -u named` to investigate signing or loading errors, and
dnsseed's output for export or reload errors.

## Links

- [BIND 9.20 DNSSEC setup and policy migration](https://bind9.readthedocs.io/en/v9.20.29/chapter5.html)
- [BIND configuration reference](https://bind9.readthedocs.io/en/v9.20.29/reference.html)
- [BIND utilities: rndc, delv and dnssec-dsfromkey](https://bind9.readthedocs.io/en/v9.20.29/manpages.html)
