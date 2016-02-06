#!/usr/bin/perl

use strict;
use warnings;
use Getopt::Std;

$Getopt::Std::STANDARD_HELP_VERSION = 1;

sub HELP_MESSAGE {
    print "SYNOPSIS\n\n" .
    "Select vertical(-v) or horizontal(-h) layout and type monitor numbers.\n" .
    "Use -l to list monitors with respective numbers and resolutions.\n";
}

sub VERSION_MESSAGE {
    print "Screen Set v0.1\nAuthor: Rayv\n\n";
}

my $xrandr_output = `xrandr`;
my %monitors;
my $counter = 0;
while ($xrandr_output =~ /(\S+) connected .+\n\W+(\S+) .+\n?/mgi) {
    $monitors{$counter++} = [$1, $2];
}

my %opts;
getopts('v:h:l', \%opts);
if (defined $opts{'l'}) {
    my $counter = 0;
    print "$_. $monitors{$_}[0] $monitors{$_}[1]\n" foreach (keys %monitors);
}

if (defined $opts{'v'}) {
    my @ordering = split " ", $opts{'v'};
    my $cmd = 'xrandr ';
    $cmd .= "--output $monitors{$ordering[0]}[0]" . 
    " --mode $monitors{$ordering[0]}[1] ";
    for my $i (1 .. $#ordering) {
        $cmd .= "--output $monitors{$ordering[$i]}[0] " .
        "--mode $monitors{$ordering[$i]}[1] " .
        "--below $monitors{$ordering[$i - 1]}[0] ";
    }
    `$cmd`;
}

if (defined $opts{'h'}) {
    my @ordering = split " ", $opts{'h'};
    my $cmd = 'xrandr ';
    $cmd .= "--output $monitors{$ordering[0]}[0]" . 
    " --mode $monitors{$ordering[0]}[1] ";
    for my $i (1 .. $#ordering) {
        $cmd .= "--output $monitors{$ordering[$i]}[0] " .
        "--mode $monitors{$ordering[$i]}[1] " .
        "--right-of $monitors{$ordering[$i - 1]}[0] ";
    }
    `$cmd`;
}
