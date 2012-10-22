use warnings;
use strict;

package XML::Compile::SOAP::WSS;
use base 'XML::Compile::SOAP::Extension';

use Log::Report 'xml-compile-wss';

use XML::Compile::WSS::Util  qw/:wss11 :utp11/;
use XML::Compile::WSS        ();
use XML::Compile::SOAP::Util qw/SOAP11ENV/;

=chapter NAME
XML::Compile::SOAP::WSS - Web Service Security used in SOAP

=chapter SYNOPSIS

 use XML::Compile::SOAP::WSDL11;
 use XML::Compile::SOAP::WSS;

 # strict order of instantiation!
 my $wss  = XML::Compile::SOAP::WSS->new; # hooks WSDL parser
 my $wsdl = XML::Compile::WSDL11->new($wsdlfn);    

 my $auth = $wss->basicAuth               # add Security record
   ( username => $user
   , password => $password
   );

 # Will include all defined security features
 my $call = $wsdl->compileClient($opname);
 my ($answer, $trace) = $call->(%data);

 # Only explicit security features:
 my $call = $wsdl->compileClient($opname);
 my ($answer, $trace) = $call->(wsse_Security => $auth, %data);
 my $trace = $call->(wsse_Security => [$auth], %data);
 
=chapter DESCRIPTION
The Web Service Security protocol is implemented in extensions of
M<XML::Compile::WSS>. This module integrates WSS in SOAP usage.

This module is an M<XML::Compile::SOAP::Extension>, a plugin for the
SOAP code.  Some of these protocols implemented with these plugins
behave badly: interfere with the WSDL specification.  Therefore, these
B<WSDL plugins> have to be B<instantiated before the WSDL> files get read.
The use of the information can only take place when all schema's are read,
so these B<security features> can only be B<created after> that.

=chapter METHODS

=section Constructors

=c_method new OPTIONS
Usually, you do not call M<new()> but one of the specific constructors.
Depends on the WSS feature you need.
=cut

sub init($)
{   my ($self, $args) = @_;
    $self->SUPER::init($args);
    $self->{XCSW_wss} = [];
    my $schema = $self->{XCSW_schema} = $args->{schema};

    # [1.0] to support backwards compat
    XML::Compile::WSS->loadSchemas($schema, '1.1') if $schema;
    $self;
}

sub wsdl11Init($$)
{   my ($self, $wsdl, $args) = @_;
    $self->SUPER::wsdl11Init($wsdl, $args);

    $self->{XCSW_schema} = $wsdl;
    XML::Compile::WSS->loadSchemas($wsdl, '1.1');
    $wsdl->prefixes('SOAP-ENV' => SOAP11ENV);

    $self;
}

sub soap11OperationInit($$)
{   my ($self, $op, $args) = @_;

    trace "adding wss header logic";  # get full type from any schema
    my $sec = $self->schema->findName('wsse:Security');
    $op->addHeader(INPUT  => "wsse_Security" => $sec);
    $op->addHeader(OUTPUT => "wsse_Security" => $sec);
}

sub soap11ClientWrapper($$$)
{   my ($self, $op, $call, $args) = @_;
    # Add empty security object, otherwise hooks will not get called.
    # May get overwritten by user supplied element or sublist of wss's.
    sub {
        my %data = @_;
        my $sec  = $data{wsse_Security};
        return $call->(%data)
            if ref $sec eq 'HASH';

        my $wss  = $sec || $self->{XCSW_wss};
        my @wss  = ref $wss eq 'ARRAY' ? @$wss : $wss;
        my $secw = $data{wsse_Security} = {};

        my $doc  = $data{_doc} ||= XML::LibXML::Document->new('1.0','UTF-8');
        $_->create($doc, $secw) for @wss;
 
        my ($answer, $trace) = $call->(%data);
        if(defined $answer)
        {   my $secr = $answer->{wsse_Security} ||= {};
            $_->check($secr) for @wss;
        }
 
        wantarray ? ($answer, $trace) : $answer;
    };
}

#---------------------------
=section Attributes

=method schema
=method wssConfigs
=method addWSS WSSOBJ
Add a new M<XML::Compile::WSS> object to the list of maintained.
=cut

sub schema()     {shift->{XCSW_schema}}
sub wssConfigs() { @{shift->{XCSW_wss}} }
sub addWSS($) { my ($wss, $n) = (shift->{XCSW_wss}, shift); push @$wss, $n; $n }

#---------------------------
=section Security features
=cut

sub _start($$)
{   my ($self, $plugin, $args) = @_;

    eval "require $plugin";
    panic $@ if $@;

    my $schema = $args->{schema} ||= $self->schema
        or error __x"instantiate {pkg} before the wsdl, plugins after"
             , pkg => __PACKAGE__;

    $self->addWSS($plugin->new($args));
}

=method basicAuth OPTIONS
Implements username/password authentication.
See documentation in M<XML::Compile::WSS::BasicAuth>.  The OPTIONS are
passed to its new() method.
=cut

sub basicAuth(%)
{   my ($self, %args) = @_;
    $self->_start('XML::Compile::WSS::BasicAuth', \%args);
}

=method timestamp OPTIONS
Adds a timestamp record to the Security header.
See documentation in M<XML::Compile::WSS::Timestamp>.  The OPTIONS are
passed to its new() method.
=cut

sub timestamp(%)
{   my ($self, %args) = @_;
    $self->_start('XML::Compile::WSS::Timestamp', \%args);
}

=method signature OPTIONS
Put a crypto signature on one or more elements.
See documentation in M<XML::Compile::WSS::Signature>.  The OPTIONS are
passed to its new() method.
=cut

sub signature(%)
{   my ($self, %args) = @_;
    my $schema = $args{schema} || $self->schema;
    my $sig    = $self->_start('XML::Compile::WSS::Signature', \%args);

    my $sign_body =
     +{ type     => 'SOAP-ENV:Body'
      , after    => sub {
          my ($doc, $xml) = @_;

          # This is called twice, caused by the trick to get first the
          # body than the header processed when writing an envelope.
          # The second time, the signature element is already prepared,
          # no signing skipped.
          $sig->signElement($xml, id => 'TheBody');  # returns a fixed elem
          $sig->createSignature($doc);
          $xml;
     }};
    $schema->declare(WRITER => 'SOAP-ENV:Envelope', hooks => $sign_body);

    my $check_body =
     +{ type   => 'SOAP-ENV:Body'
      , before => sub {
          my ($node, $path) = @_;
          $sig->checkElement($node);
      }};
    $schema->declare(READER => 'SOAP-ENV:Envelope', hooks => $check_body);

    $sig;
}

#--------------------------------------
# [1.0] Expired interface
sub wsseBasicAuth($$$@)
{   my ($self, $username, $password, $pwtype, %args) = @_;
    # use XML::Compile::WSS::BasicAuth!!!  The method will be removed!

    eval "require XML::Compile::WSS::BasicAuth";
    panic $@ if $@;

    my $auth = XML::Compile::WSS::BasicAuth->new
      ( username  => $username
      , password  => $password
      , pwformat  => $pwtype || UTP11_PTEXT
      , %args
      , schema    => $self->schema
      );

   my $doc  = XML::LibXML::Document->new('1.0', 'UTF-8');
   $auth->create($doc, {});
}

# [1.0] Expired interface
sub wsseTimestamp($$$@)
{   my ($self, $created, $expires, %args) = @_;
    # use XML::Compile::WSS::Timestamp!!!  The method will be removed!

    eval "require XML::Compile::WSS::Timestamp";
    panic $@ if $@;

    my $ts = XML::Compile::WSS::Timestamp->new
      ( created => $created 
      , expires => $expires
      , %args
      , schema  => $self->schema
      );

   my $doc  = XML::LibXML::Document->new('1.0', 'UTF-8');
   $ts->create($doc, {});
}
 

1;
