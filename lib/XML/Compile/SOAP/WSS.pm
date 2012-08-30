use warnings;
use strict;

package XML::Compile::SOAP::WSS;
use base 'XML::Compile::WSS', 'XML::Compile::SOAP::Extension';

use Log::Report 'xml-compile-wss';

use XML::Compile::WSS::Util ':wss11';
#use XML::Compile::SOAP::Util qw/WSDL11/;

=chapter NAME
XML::Compile::SOAP::WSS - Web Service Security used in SOAP

=chapter SYNOPSIS

 # use WSS via WSDL,
 use XML::Compile::SOAP::WSDL11;  # first
 use XML::Compile::SOAP::WSS;     # hooks into wsdl

 # you really need next line
 my $wss  = XML::Compile::SOAP::WSS->new(version => '1.1');

 my $wsdl = XML::Compile::WSDL11->new(...);
 my $call = $wsdl->compileClient('some_operation');

 # security header fields start with wss_ or wsu_
 my $token = $wss->wsseBasicAuth($user, $password);
 my ($data, $trace) = $call->(wsse_Security => $token, %data);

=chapter DESCRIPTION
The Web Service Security protocol is implemented by the super
class M<XML::Compile::WSS>. This extension seeks to integrate
that specification with SOAP.

=chapter METHODS

=section Constructors

=c_method new OPTIONS
=cut

sub init($)
{   my ($self, $args) = @_;
    $self->XML::Compile::WSS::init($args);
    $self->XML::Compile::SOAP::Extension::init($args);
}

sub wsdl11Init($$)
{   my ($self, $wsdl, $args) = @_;

    # When no new(schema) is given, we need to load the schemas now
    $self->schema || $self->loadSchemas($wsdl);
}

sub soap11OperationInit($$)
{   my ($self, $op, $args) = @_;

    trace "adding wss header logic";
    my $sec = $self->schema->findName('wsse:Security');
    $op->addHeader(INPUT  => "wsse_Security" => $sec);
    $op->addHeader(OUTPUT => "wsse_Security" => $sec);
}

1;
