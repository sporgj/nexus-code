#!/usr/bin/perl

$filename = shift (@ARGV);

open FILE, ">$filename";

print FILE "create " . shift . "\n";



$type_str = "addmod";

foreach $val (@ARGV) {

  if ($val eq "LIBS") {
    $type_str = "addlib";
    next;
  }

  print FILE "$type_str $val\n";

}

print FILE "save\n";
print FILE "end\n";


close FILE;
