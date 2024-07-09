#!/usr/bin/perl -w

use strict;
use warnings;
use E32::EIF;
use Try::Tiny;

my($arg);
my($args) = new E32::EIF::vector_string();

while(($arg = shift(@ARGV)))
{
	$args->push($arg);
}

my($capture);

try
{
	my($e32if) = new E32::EIF::E32If($args);
}
catch
{
	printf STDERR ("failed: %s\n", $_);
}
