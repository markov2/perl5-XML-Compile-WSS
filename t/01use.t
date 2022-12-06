#!/usr/bin/env perl
use warnings;
use strict;

use lib 'lib';
use Test::More tests => 4;

# The versions of the following packages are reported to help understanding
# the environment in which the tests are run.  This is certainly not a
# full list of all installed modules.
my @show_versions =
 qw/Test::More
    XML::Compile
    XML::Compile::Cache
    XML::Compile::SOAP
    Log::Report
    Encode
    MIME::Base64
   /;

foreach my $package (@show_versions)
{   eval "require $package";

    no strict 'refs';
    my $report
      = !$@    ? "version ". (${"$package\::VERSION"} || 'unknown')
      : $@ =~ m/^Can't locate/ ? "not installed"
      : "reports error";

    warn "$package $report\n";
}

require_ok('XML::Compile::WSS::Util');
require_ok('XML::Compile::WSS');
require_ok('XML::Compile::WSS::BasicAuth');
require_ok('XML::Compile::SOAP::WSS');
