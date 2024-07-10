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
my($e32if) = new E32::EIF::E32If;

try
{
	$e32if->run($args);
}
catch
{
	printf STDERR ("failed: %s\n", $_);
	exit(1);
};

printf STDOUT ("%s", $e32if->get());
