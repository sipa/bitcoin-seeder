# DNSSEC setup for dnsseed

This guide is for a new installation on Debian GNU/Linux 13 (trixie), tested
with BIND **9.20.29-1~deb13u1**. BIND serves a signed public DNS zone; an
unprivileged bitcoin-seeder listens on loopback, and an hourly script copies
its A and AAAA records into BIND using authenticated dynamic updates.

- [Requirements](#requirements)
- [Install software](#install-software)
- [Configure BIND](#configure-bind)
- [Build and start bitcoin-seeder](#build-and-start-bitcoin-seeder)
- [Install the updater](#install-the-updater)
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

Create an A record (and an AAAA record if IPv6 is available) for
`dnsseed-host.example.com` in the **parent** zone, pointing to this machine's
public address. This hostname is outside `dnsseed.example.com`, so its
address belongs in the parent zone, not in the seed zone. If you instead use
an NS hostname inside the seed zone, add its address to the seed zone and
publish the corresponding glue at the parent.

Run the installation and BIND configuration commands below as root. Build
and run bitcoin-seeder as an ordinary user. Tor is not needed for this setup.

## Install software

```sh
apt update
apt install bind9 bind9-dnsutils bind9-utils
```

Allow inbound TCP and UDP port 53 in your firewall. Keep the seeder's UDP
port 15353 private. If you use UFW, allow your actual SSH port before enabling
it (the example assumes port 22):

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

Create a writable directory for the zone, journals and DNSSEC keys:

```sh
install -d -o bind -g bind -m 0750 /var/lib/bind/dnsseed.example.com
```

Create `/var/lib/bind/dnsseed.example.com/db.dnsseed.example.com`:

```dns
$ORIGIN dnsseed.example.com.
$TTL 3600
@ IN SOA dnsseed-host.example.com. contact-email.example.com. (
    1       ; initial serial (BIND increments it for dynamic updates)
    3600    ; refresh
    600     ; retry
    86400   ; expire
    600     ; negative cache TTL
)
@ IN NS dnsseed-host.example.com.
```

No dummy address record is needed. The explicit `$ORIGIN` keeps relative
names inside the seed zone. Set the file ownership:

```sh
chown bind:bind /var/lib/bind/dnsseed.example.com/db.dnsseed.example.com
chmod 0640 /var/lib/bind/dnsseed.example.com/db.dnsseed.example.com
```

Add this zone to `/etc/bind/named.conf.local`:

```conf
zone "dnsseed.example.com" {
    type primary;
    file "/var/lib/bind/dnsseed.example.com/db.dnsseed.example.com";
    key-directory "/var/lib/bind/dnsseed.example.com";
    update-policy local;
    dnssec-policy default;
    inline-signing yes;
};
```

`update-policy local` requires BIND's generated local TSIG session key;
`nsupdate -l` uses that key. It replaces unauthenticated `allow-update
{ localhost; };`. Root can read `/run/named/session.key` on Debian; do not
make this key world-readable.

`dnssec-policy default` generates a combined signing key using
ECDSAP256SHA256 and maintains the signatures automatically. BIND manages the
`.signed` file and its format. Do not manually generate keys, include DNSKEY
files, or run `dnssec-signzone` for this setup. The policy uses NSEC, so no
NSEC3 salt is needed. The old `dnssec-enable`, `auto-dnssec` and
`dnssec-keygen -r` commands are obsolete in BIND 9.20.

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

As an ordinary user, clone and build the repository:

```sh
git clone https://github.com/sipa/bitcoin-seeder.git
cd bitcoin-seeder
make
./dnsseed -a 127.0.0.1 -p 15353 -h dnsseed.example.com \
    -n dnsseed-host.example.com -m contact-email.example.com
```

The seeder uses UDP and binds only to loopback. Port 15353 avoids the mDNS
port 5353. Keep the process running (for example under a service manager).
Its database needs time to collect reliable peers; a successful DNS response
can initially have no A or AAAA answers.

```sh
dig @127.0.0.1 -p 15353 dnsseed.example.com A +norecurse
dig @127.0.0.1 -p 15353 x49.dnsseed.example.com AAAA +norecurse
```

## Install the updater

Use [contrib/dnsupdate](contrib/dnsupdate) from this change. The following
commands assume your current directory is the repository checkout:

```sh
install -m 0755 contrib/dnsupdate /usr/local/sbin/dnsupdate
/usr/local/sbin/dnsupdate -h dnsseed.example.com -a 127.0.0.1 -p 15353
```

The updater copies the apex and the default whitelisted filter names. It
updates only their A and AAAA records, preserving the SOA, NS and DNSSEC
records. It fetches all answers before sending one transaction to local BIND.
A timeout or DNS error aborts the update and preserves the previous records;
a successful empty answer removes the corresponding stale address records.

For a custom seeder whitelist, pass matching space-separated DNS filter names
with `-w`, for example `-w 'x1 x9 x49'`. Use `-w ''` for the apex only.
The defaults include the current P2P v2 filters `x809`, `x849`, `xc08`, and
`xc48`. The seeder's own `-w` option takes numeric flag combinations instead.

Create `/etc/cron.d/dnsseed-update` with this content (and a final newline):

```cron
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
7 * * * * root /usr/local/sbin/dnsupdate -h dnsseed.example.com -a 127.0.0.1 -p 15353
```

Install and enable cron if it is not already running:

```sh
apt install cron
systemctl enable --now cron
```

The script is silent on success; keep cron error reporting configured.
For multiple seeds, give each a separate
BIND zone, seeder process/database directory, private UDP port, and cron line.

For a dedicated non-root updater, configure an explicit TSIG key with an
`update-policy` granting only A/AAAA updates in its zone, give that user read
access to the key, and pass `-k /path/to/key`. This mode sends authenticated
updates to BIND at `127.0.0.1:53`; do not combine an explicit `update-policy`
with `update-policy local` in the same zone.

Once a zone is dynamic, use `nsupdate` for changes. If you must edit its file,
use `rndc freeze dnsseed.example.com` first and `rndc thaw dnsseed.example.com`
afterward. Back up the DNSSEC keys and zone data.

## Publish the delegation and DS record

Wait until BIND serves a DNSKEY and its signature:

```sh
dig @127.0.0.1 dnsseed.example.com DNSKEY +dnssec +norecurse
```

Export the **published** DNSKEY records and derive the SHA-256 DS record:

```sh
dig @127.0.0.1 dnsseed.example.com DNSKEY +noall +answer > /tmp/dnsseed-dnskey.txt
dnssec-dsfromkey -2 -f /tmp/dnsseed-dnskey.txt dnsseed.example.com
```

Expect a DS record containing the key tag, algorithm `13`, digest type `2`,
and a hexadecimal digest. No `dsset-*` file or manual signing step is needed.

In the parent zone, delegate `dnsseed.example.com` with an NS record pointing
to `dnsseed-host.example.com`. Once the nameserver is publicly reachable and
serving signatures, publish the derived DS record in that parent zone (or
through the registrar if it manages that delegation). A DS record for this
seed subdomain belongs at its delegation, not automatically at `example.com`'s
registry delegation.

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
Use `journalctl -u named` to investigate signing or dynamic-update errors.

The Debian 13 / BIND 9.20.29 test used an isolated loopback instance. It checked
configuration and zone loading, automatic signing, authenticated A/AAAA
updates at the apex and filter names, signature validation with a local trust
anchor, and preserving existing records when the source fails. Public
NS/DS delegation requires your real domain and is a separate deployment step.

## Links

- [BIND 9.20 DNSSEC setup and policy migration](https://bind9.readthedocs.io/en/v9.20.29/chapter5.html)
- [BIND configuration reference](https://bind9.readthedocs.io/en/v9.20.29/reference.html)
- [BIND utilities: nsupdate, delv and dnssec-dsfromkey](https://bind9.readthedocs.io/en/v9.20.29/manpages.html)
