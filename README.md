SUGARCHAIN-SEEDER
==============

sugarchain-seeder is a crawler for the Sugarchain network, which exposes a list of reliable nodes via a built-in DNS server.

Features:
* regularly revisits known nodes to check their availability
* bans nodes after enough failures, or bad behaviour
* accepts nodes from Yumekawa v0.16.3.x (protocol version `70015`) to request new IP addresses.
* keeps statistics over (exponential) windows of 2 hours, 8 hours, 1 day and 1 week, to base decisions on.
* very low memory (a few tens of megabytes) and cpu requirements.
* crawlers run in parallel (by default `96` threads simultaneously).

INSTALLATION
------------

```bash
cd && \
sudo apt-get update && \
sudo apt-get install -y build-essential libboost-all-dev libssl-dev && \
git clone https://github.com/sugarchain-project/sugarchain-seeder.git && \
cd sugarchain-seeder && \
make -j$(nproc)
```

USAGE
-----

On the system `1ns-testnet.cryptozeny.com`, you can now run dnsseed with root privileged to use port 53 (`UDP`)
```bash
sudo ./dnsseed --testnet -h 1seed-testnet.cryptozeny.com -n 1ns-testnet.cryptozeny.com -m cryptozeny.gmail.com
```

Assuming you want to run a dns seed on `1seed-testnet.cryptozeny.com`, you will need an authorative NS record in `sugarchain.org`'s domain record, pointing to for example `1ns-testnet.cryptozeny.com`:

```bash
dig -t NS 1seed-testnet.cryptozeny.com
```

```
;; ANSWER SECTION:
1seed-testnet.cryptozeny.com. 21599 IN	NS	1ns-testnet.cryptozeny.com.
```

If you want the DNS server to report SOA records, please provide an e-mail address (with the `@` part replaced by `.`) using `-m`.

Check if port 53 opened
```bash
sudo netstat -nulp | grep 53

udp6       0      0 :::53                   :::*                                10949/dnsseed
```

Check if it works
```bash
watch -n1 dig +short -t A 1seed-testnet.cryptozeny.com @1.1.1.1
```

Run Sugarchain node on another computer
```bash
./src/sugarchaind -testnet -dns=1 -dnsseed=1 -forcednsseed=1 -listen=1 -daemon
```

CRON
----
Adding following command with `sudo crontab -e` as `@reboot`. On amazon AWS EC2, run with `crontab -e` (without sudo because the username is ubuntu)

`1seed-testnet.cryptozeny.com`
```bash
@reboot sudo $HOME/sugarchain-seeder/dnsseed --testnet -h 1seed-testnet.cryptozeny.com -n 1ns-testnet.cryptozeny.com -m cryptozeny.gmail.com
```

RUNNING AS NON-ROOT
-------------------

Typically, you'll need root privileges to listen to port 53 (name service). One solution is using an iptables rule (Linux only) to redirect it to a non-privileged port:

```bash
iptables -t nat -A PREROUTING -p udp --dport 53 -j REDIRECT --to-port 5353
```

If properly configured, this will allow you to run dnsseed in userspace, using the -p 5353 option.
