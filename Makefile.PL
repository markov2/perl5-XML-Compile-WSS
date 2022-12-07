# This code is part of distribution XML-Compile-WSS.  Meta-POD processed
# with OODoc into POD and HTML manual-pages.  See README.md
# Copyright Mark Overmeer.  Licensed under the same terms as Perl itself.

use ExtUtils::MakeMaker;
use warnings;
use strict;

use 5.010;

# Signatures MUST be upgraded when installed

eval "require XML::Compile::WSS::Signature";
my $version = $XML::Compile::WSS::Signature::VERSION;

if(defined $version && $version lt '2.00')
{   warn <<__WARN;
*************
    You have XML::Compile::WSS::Signature version $version installed,
    but MUST upgrade it to at least version 2.00
*************
__WARN
    sleep 15
}

WriteMakefile
 ( NAME	 		=> 'XML::Compile::WSS'
 , VERSION 		=> '1.15'

 , PREREQ_PM    =>
     { 'XML::Compile'         => '1.50'
     , 'XML::Compile::Cache'  => '1.00'
     , 'XML::Compile::SOAP'   => '3.00'
     , 'XML::Compile::WSDL11' => '3.00'
     , 'Log::Report'          => '0.92'

     , 'Encode'               => 0
     , 'Test::More'           => 0.54
     , 'File::Basename'       => 0
     , 'MIME::Base64'         => 0
     , 'Digest::SHA'          => 0
     , 'Scalar::Util'         => 0
     }
 , EXE_FILES    => []
 , AUTHOR       => 'Mark Overmeer <markov@cpan.org>'
 , ABSTRACT     => 'OASIS Web Services Security'
 , LICENSE      => 'perl_5'

 , META_MERGE =>
      { 'meta-spec' => { version => 2 }
      , resources  =>
          { repository =>
              { type => 'git'
              , url  => 'https://github.com/markov2/perl5-XML-Compile-WSS.git'
              , web  => 'https://github.com/markov2/perl5-XML-Compile-WSS'
              }
          , homepage => 'http://perl.overmeer.net/CPAN/'
          , license  => [ 'http://dev.perl.org/licenses/' ]
          }
      }
 );

### used by oodist during production of distribution
sub MY::postamble { <<'__POSTAMBLE' }

# for DIST
RAWDIR          = ../public_html/xml-compile-wss/raw
DISTDIR         = ../public_html/xml-compile-wss/source

# for POD
FIRST_YEAR      = 2011
EMAIL           = mark@overmeer.net
EXTENDS         = ../XML-Compile:../XML-Compile-Cache:../XML-Compile-C14N:../XML-Compile-WSS-Signature
WEBSITE         = http://perl.overmeer.net/xml-compile/
__POSTAMBLE
