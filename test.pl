#!/usr/bin/perl

use threads;
use threads::shared;
use bytes;
use IO::Socket;
use strict;

my @dom = ("seed1","blocknet","co");

my $run :shared = 1;

sub go {
  my ($idx) = @_;

  my $runs = 0;
  
  my $sock = IO::Socket::INET->new(
    Proto    => 'udp',
    PeerPort => 53,
    PeerAddr => "seed1.blocknet.co",
  ) or die "Could not create socket: $!\n";

  while($run) {

    my $id = int(rand(65536));
    my $qr = 0;
    my $opcode = 0;
    my $aa = 0;
    my $tc = 0;
    my $rd = 0;
    my $ra = 0;
    my $z = 0;
    my $rcode = 0;
    my $qdcount = 1;
    my $ancount = 0;
    my $nscount = 0;
    my $arcount = 0;
    my $header = pack('nnnnnn',$id,1*$qr + 2*$opcode + 32*$aa + 64*$tc + 128*$rd + 256*$ra + 512*$z + 4096*$rcode, $qdcount, $ancount, $nscount, $arcount);
    my $qtype = 1; # A record
    my $qclass = 1; # IN class
    my $query = (join("", map { chr(length($_)) . $_ } (@dom,""))) . pack('nn',$qtype,$qclass);
    my $msg = $header . $query;
    $sock->send($msg);
    my $resp;
    $runs++ if ($sock->recv($resp, 512, 0));
    
#    $sock->close();
  }
  return $runs;
}

my @threads;

for my $i (0..500) {
  $threads[$i] = threads->create(\&go, $i);
}

sleep 10;

$run=0;
my $runs = 0;
foreach my $thr (@threads) {
  $runs += $thr->join();
}

print "$runs runs\n";
