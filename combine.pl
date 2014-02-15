#!/usr/bin/perl -w

use strict;

sub loadFile {
  my ($file) = @_;
  my %ret;
  my $max = 0;
  open FILE,$file;
  while (<FILE>) {
    my ($addr,$p2h,$p8h,$p1d,$p1w,$p1m) = split(/\s+/,$_);
    if ($p1m =~ /\A([1-9.]+)%\Z/) {
      my $x = $1*0.01;
      $max=$x if ($x > $max);
      $ret{$addr} = $x;
    }
  }
  for my $k (keys %ret) {
    $ret{$k} /= $max;
  }
  close FILE;
  return \%ret;
}

sub merge {
  my ($a,$b) = @_;
  return 1-(1-$a)*(1-$b);
}

sub combine {
  my ($f1,$f2) = @_;
  my %ret;
  for my $k1 (keys %{$f1}) {
    if (defined $f2->{$k1}) {
      $ret{$k1} = merge($f1->{$k1}, $f2->{$k1});
    } else {
      $ret{$k1} = merge($f1->{$k1}, 0);
    }
  }
  for my $k2 (keys %{$f2}) {
    if (!defined $f1->{$k2}) {
      $ret{$k2} = merge(0, $f2->{$k2});
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

for my $addr (sort { $res->{$b} <=> $res->{$a} } (keys %{$res})) {
  if ($addr =~ /\A(\d+)\.(\d+)\.(\d+)\.(\d+):11556/) {
    my $a = $1*0x1000000 + $2*0x10000 + $3*0x100 + $4;
    printf "0x%08x %s %g%%\n",$a,$addr,(1-((1-$res->{$addr}) ** (1/$n)))*100;
  }
}
