#!/usr/bin/env perl
#
# Verify that, when "created" is passed as a number in wsseBasicAuth,
# it gets encrypted the right way.  Check using both integer and
# string timestamps, with Nonce and without.
#
# In version 0.90, this was not true.
#

use strict ;
use warnings ;

use Digest::SHA     qw/sha1_base64/;
use Encode          qw/encode/;
use MIME::Base64    qw/encode_base64 decode_base64/ ;

use Test::More tests => 24 ;

use XML::Compile::WSDL11;
use XML::Compile::SOAP::WSS;
use XML::Compile::WSS::Util qw/:utp11/;

my ($username, $password) = qw/username password/;

my $wsdl     = XML::Compile::WSDL11->new('t/example.wsdl');
my $wss      = XML::Compile::SOAP::WSS->new(version => 1.1, schema => $wsdl);

my $now      = time() ;
my $nonce    = 'insecure' ;

my $untype   = $wss->schema->findName('wsse:UsernameToken');
my $unreader = $wss->schema->reader($untype) ;

my @testCases = ( { nonce => $nonce, created => $now, _explain => 'integer, with Nonce' },
                  { created => $now, _explain => 'integer, no Nonce' },
                  { nonce => $nonce, created => '2012-08-17T12:02:26Z', _explain => 'string, with Nonce' },
                  { created => '2012-08-17T12:02:26Z', _explain => 'string, no Nonce' },
              ) ;

foreach my $t (@testCases) {
    my $explain = delete $t->{_explain} || 'huh??' ;

    my $usernameToken = $wss->wsseBasicAuth($username, $password, UTP11_PDIGEST
                                                , %$t
                                            );
    ok($usernameToken, "PasswordDigest returns something sensible, $explain");
    my $utString = $usernameToken->{$untype}->toString() ;

    ok( my $p = eval { $unreader->($utString) }
            , "UsernameToken is legible, $explain" )
        or do { diag($@) ; diag( "Bad string (skip encryption test):\n$utString" ) } ;
  SKIP: {
        # Only check encryption if there's a valid interpretation in
        # the first place, because it ain't going to work otherwise.
        # And the failure above means the whole test is going to be a
        # failure anyway.
        skip 'UsernameToken is illegible' => 4 unless $p ;

        checkEncryption( $p, $t->{nonce}, $password, $explain ) ;
    } ;
}


# Verify that, if one unpacks the Nonce and Created from the
# UsernameToken, the SHA1 goes back together the right way.
#
# This method always runs four tests.  Probably, this should just
# become a subtest; then we could remove the "free pass"
sub checkEncryption {
    my ($un, $nonce, $password, $explain) = @_ ;

    $nonce ||= '' ;
    if( $nonce ) {
        my $enc = $un->{wsse_Nonce}->{_} ;
        ok( $enc, 'Nonce is required and present' ) ;
        is( decode_base64( $enc ), $nonce, 'Nonce decodes correctly' )
    }
    else {
        ok( ! $un->{wsse_Nonce}, 'Nonce is appropriately absent' ) ;
        ok( 1, 'Free pass, to make the test-counts balance' ) ;
    }

    ok( $un->{wsu_Created}->{_}, "Created is present, $explain" ) ;
        # or diag( Data::Dumper->Dump( [$un], ['usernametoken'] ) ) ;
    my $plainPassword = join( '', $nonce, $un->{wsu_Created}->{_}, $password ) ;

    is( sha1_base64(encode( utf8 => $plainPassword )) . '=', $un->{wsse_Password}->{_},
        "Password is encrypted correctly, $explain" ) ;
}
