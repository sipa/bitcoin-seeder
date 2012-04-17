#!/usr/bin/perl -w

use strict;

sub loadFile {
  my ($file) = @_;
  my %ret;
  my $min = 100000000;
  open FILE,$file;
  while (<FILE>) {
    my ($addr,$p2h,$p8h,$p1d,$p1w,$p1m) = split(/\s+/,$_);
    if ($p1m =~ /\A([1-9.]+)%\Z/) {
      my $x = log($1*0.01)/log(0.5);
      $min=$x if ($x < $min);
      $ret{$addr} = $x;
    }
  }
  for my $k (keys %ret) {
    $ret{$k} -= $min;
  }
  close FILE;
  return \%ret;
}

sub combine {
  my ($f1,$f2) = @_;
  my %ret;
  for my $k1 (keys %{$f1}) {
    if (defined $f2->{$k1}) {
      $ret{$k1} = $f1->{$k1} + $f2->{$k1};
    }
  }
  return \%ret;
}

my $res;
my $n=0;
for my $file (@ARGV) {
  my $r = loadFile($file);
  if ($res) {
    $res = combine($res,$r);
  } else {
    $res = $r;
  }
  $n++;
}

for my $addr (sort { $res->{$a} <=> $res->{$b} } (keys %{$res})) {
  if ($addr =~ /\A(\d+)\.(\d+)\.(\d+)\.(\d+):8333/) {
    my $a = $1*0x1000000 + $2*0x10000 + $3*0x100 + $4;
    printf "0x%08x %s %g%%\n",$a,$addr,exp(log(0.5)*$res->{$addr}/$n)*100;
  }
}
