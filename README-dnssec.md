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
- [Configure zone reloads](#configure-zone-reloads)
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
apt install bind9 bind9-dnsutils bind9-utils sudo
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

Keep the `seeder` user out of the `bind` group: members can read
`/etc/bind/rndc.key` and administer BIND with `rndc`. Instead, give the
crawler its own export directory and allow only a specific reload command
through `sudo`. Keep DNSSEC keys in a BIND-owned directory that the crawler
cannot access.

Create both directories. BIND needs write access to the export directory for
its signed zone and journals. The setgid bit makes new exports inherit the
`bind` group without giving `seeder` membership of that group. Debian and
Ubuntu's AppArmor profiles allow BIND to write under `/var/lib/bind`.

```sh
install -d -o seeder -g bind -m 2770 /var/lib/bind/dnsseed.example.com-export
install -d -o bind -g bind -m 0750 /var/lib/bind/dnsseed.example.com
```

Create an initial `/var/lib/bind/dnsseed.example.com-export/db.dnsseed.example.com`,
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
chown seeder:bind /var/lib/bind/dnsseed.example.com-export/db.dnsseed.example.com
chmod 0640 /var/lib/bind/dnsseed.example.com-export/db.dnsseed.example.com
```

Add this zone to `/etc/bind/named.conf.local`:

```conf
zone "dnsseed.example.com" {
    type primary;
    file "/var/lib/bind/dnsseed.example.com-export/db.dnsseed.example.com";
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
named-checkzone dnsseed.example.com /var/lib/bind/dnsseed.example.com-export/db.dnsseed.example.com
systemctl restart named
systemctl --no-pager status named
journalctl -u named --since '5 minutes ago' --no-pager
```

`named-checkconf` should exit successfully without output, and
`named-checkzone` should report `loaded serial 1` and `OK` for the initial
file. BIND's service is `named.service` on Debian and Ubuntu.

## Configure zone reloads

As root, use `visudo` to create `/etc/sudoers.d/dnsseed-zone-reload`, owned by
root with mode `0440`:

```sh
visudo -f /etc/sudoers.d/dnsseed-zone-reload
```

Add this rule, replacing the user and zone name consistently:

```sudoers
seeder ALL=(root) NOPASSWD: /usr/sbin/rndc -k /etc/bind/rndc.key -s 127.0.0.1 reload dnsseed.example.com
```

The rule matches the complete command and its arguments, allowing the
crawler to reload only its own zone without reading BIND's administrative
key. Do not omit the arguments or use wildcards: that would grant broader
access. The crawler must not be able to modify this file or the `rndc`
executable. Check the configuration:

```sh
visudo -c
```

The `-k` and `-s` arguments match BIND's default control channel on Debian
(no `controls` statement in the configuration, and the key in
`/etc/bind/rndc.key`). If you configured a different one, adjust them in both
this rule and dnsseed's `--zone-reload` command below.

sudo logs every reload, by default every 2 minutes, along with a PAM session
for each. To keep these out of the system logs, you can add this line to the
same file, at the cost of also not logging failed attempts by that user
(dnsseed still reports failed reloads in its output):

```sudoers
Defaults:seeder !syslog, !pam_session
```

This works with the classic sudo, the default on Debian. sudo-rs (the default
on recent Ubuntu releases) does not support these settings, and `visudo -c`
rejects them there; leave the line out in that case.

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
umask 0027
./dnsseed -h dnsseed.example.com -n dnsseed-host.example.com \
    -m contact-email.example.com --nodns \
    --zonefile /var/lib/bind/dnsseed.example.com-export/db.dnsseed.example.com \
    --zone-reload "/usr/bin/sudo -n /usr/sbin/rndc -k /etc/bind/rndc.key -s 127.0.0.1 reload dnsseed.example.com"
```

Keep the process running (for example under a service manager), always from
the same directory: its database (`dnsseed.dat`) is stored there. `--nodns`
disables the built-in DNS server, so dnsseed needs no open ports and runs as
an ordinary user; only its fixed reload command runs as root through `sudo`.

BIND reads the exported files through the inherited `bind` group; the umask
additionally keeps other users from reading them (BIND does not need it).
If you run the crawler under systemd, include these settings in its unit so
BIND starts before the crawler, exported files retain these permissions,
and `sudo` can acquire the privileges needed for the reload:

```ini
[Unit]
Wants=named.service
After=named.service

[Service]
UMask=0027
NoNewPrivileges=false
```

`NoNewPrivileges=true` prevents `sudo` from gaining root privileges, even
with a matching sudoers rule. Test the reload from the same service sandbox
if you add other hardening settings. `sudo -n` fails instead of prompting
for a password, so authorization and reload errors appear in dnsseed's output.

Every 2 minutes (see `--zone-interval`), dnsseed replaces the zone file and
runs the reload command. The zone contains the SOA and NS records (from `-h`,
`-n` and `-m`), and A and AAAA records, randomly selected from the good
nodes, at the zone apex and at each filter name that the seeder supports
(such as `x9.dnsseed.example.com`; see its `-w` option).

The number of A and AAAA records per name is as many as fit in a 512-byte
answer, with room for an EDNS OPT record and DNS cookie (26 A or 15 AAAA
records for `dnsseed.example.com`; fewer for longer names). That is the limit
for clients that don't use EDNS when asking their resolver (such as glibc's
resolver, unless `options edns0` is set), or use it with a 512-byte buffer.
Larger answers make those clients retry over TCP, and their lookup fails
entirely if that doesn't work (glibc doesn't use the truncated answer).
Between resolvers and BIND, EDNS is used, and signed answers fit in the usual
1232-byte buffer.

The TTL of the records is the export interval. Unlike with the built-in DNS
server, which selects addresses for every query, all clients get the same
addresses until the next export; a short interval makes clients of different
resolvers get different addresses over time.

The database needs time to collect reliable nodes. Nothing is exported until
there are good nodes; if there are none (for example when starting with an
empty database), the previous zone file is kept.

For multiple seeds, give each a separate BIND zone, crawler user, database
directory, export directory, and DNSSEC key directory. Add a separate sudoers
rule for each crawler, restricting its reload command to its own zone.

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

As root, check that the crawler cannot read BIND's administrative key or
access the DNSSEC key directory, and reload the zone as the crawler user:

```sh
runuser -u seeder -- test ! -r /etc/bind/rndc.key
runuser -u seeder -- test ! -x /var/lib/bind/dnsseed.example.com
runuser -u seeder -- /usr/bin/sudo -n /usr/sbin/rndc -k /etc/bind/rndc.key -s 127.0.0.1 reload dnsseed.example.com
```

Both permission checks and the reload command should exit successfully.

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
