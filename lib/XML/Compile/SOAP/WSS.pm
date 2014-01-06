use warnings;
use strict;

package XML::Compile::SOAP::WSS;
use base 'XML::Compile::SOAP::Extension';

use Log::Report 'xml-compile-wss';

use XML::Compile::WSS::Util  qw/:wss11 :utp11/;
use XML::Compile::WSS        ();
use XML::Compile::SOAP::Util qw/SOAP11ENV/;

use Scalar::Util             qw/weaken/;

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
 my $call     = $wsdl->compileClient($opname);
 my ($answer, $trace) = $call->(%data);

 # Only explicit security features:
 my $call     = $wsdl->compileClient($opname);
 my ($answer, $trace) = $call->(wsse_Security => $auth, %data);

 my @features = ($auth, ...);    # any selection of features
 my $answer   = $call->(wsse_Security => \@features, %data);
 
=chapter DESCRIPTION
The Web Service Security protocol is implemented in the sub-classes of
M<XML::Compile::WSS>. This module integrates WSS features in SOAP usage.

This module is an M<XML::Compile::SOAP::Extension>; a plugin for the
SOAP infra-structure.  Many of these extension protocols behave badly:
they usually interfere with the WSDL specification.  Therefore, all
B<WSDL plugins> have to be instantiated before the WSDL files get read,
i.e. before the WSDL object itself gets instantiated.  The use of the
information can only take place when all schema's are read, so these
security features can only be created after that.

=chapter METHODS

=section Constructors

=c_method new OPTIONS
=option  schema M<XML::Compile::Cache> object
=default schema C<undef>
Do not use this in combination with a WSDL, but always in any other case.
=cut

sub init($)
{   my ($self, $args) = @_;
    $self->SUPER::init($args);
    $self->{XCSW_wss} = [];

    my $schema = $self->{XCSW_schema} = $args->{schema};
    weaken $self->{XCSW_schema};

    # [1.0] to support backwards compat
    XML::Compile::WSS->loadSchemas($schema, '1.1') if $schema;
    $self;
}

sub wsdl11Init($$)
{   my ($self, $wsdl, $args) = @_;
    $self->SUPER::wsdl11Init($wsdl, $args);

    $self->{XCSW_schema} = $wsdl;
    weaken $self->{XCSW_schema};

    XML::Compile::WSS->loadSchemas($wsdl, '1.1');
    $wsdl->addPrefixes('SOAP-ENV' => SOAP11ENV);

    $self;
}

sub soap11OperationInit($$)
{   my ($self, $op, $args) = @_;

    my $schema = $self->schema
        or error __x"WSS not connected to the WSDL: WSS needs to be instantiated
before the WSDL because it influences its interpretation";

    trace "adding wss header logic";  # get full type from any schema
    my $sec = $schema->findName('wsse:Security');
    $op->addHeader(INPUT  => "wsse_Security" => $sec, mustUnderstand => 1);
    $op->addHeader(OUTPUT => "wsse_Security" => $sec, mustUnderstand => 1);
}
*soap12OperationInit = \&soap11OperationInit;

sub soap11ClientWrapper($$$)
{   my ($self, $op, $call, $args) = @_;
    sub {
        my $data = @_==1 ? shift : {@_};
        my $sec  = $data->{wsse_Security};

        # Support pre-1.0 interface
        return $call->($data)
            if ref $sec eq 'HASH';

        # select plugins
        my $wss  = $sec || $self->{XCSW_wss};
        my @wss  = ref $wss eq 'ARRAY' ? @$wss : $wss;

        # Adding WSS headers to $secw
        my $secw = $data->{wsse_Security} = {};
        my $doc  = $data->{_doc} ||= XML::LibXML::Document->new('1.0','UTF-8');
        $_->create($doc, $secw) for @wss;
 
        # The real work: SOAP message formatting and exchange
        my ($answer, $trace) = $call->($data);

        if(defined $answer)
        {   my $secr = $answer->{wsse_Security} ||= {};
            $_->check($secr) for @wss;
        }
 
        wantarray ? ($answer, $trace) : $answer;
    };
}
*soap12ClientWrapper = \&soap11ClientWrapper;

#---------------------------
=section Attributes

=method schema

=method features
Returns a list of all security features.

=method addFeature WSSOBJ
Add a new M<XML::Compile::WSS> object to the list of maintained features.
=cut

sub schema()   { shift->{XCSW_schema} }
sub features() { @{shift->{XCSW_wss}} }

sub addFeature($)
{   my ($self, $n) = @_;
    my $schema = $n->schema
        or error __x"no schema yet. Instantiate ::WSS before ::WSDL";

    push @{$self->{XCSW_wss}}, $n;
    $n;
}

#---------------------------
=section Security features
Create one or more of these "features", components in the security
header.
=cut

sub _start($$)
{   my ($self, $plugin, $args) = @_;

    eval "require $plugin";
    panic $@ if $@;

    my $schema = $args->{schema} ||= $self->schema
        or error __x"instantiate {pkg} before the wsdl, plugins after"
             , pkg => __PACKAGE__;

    $self->addFeature($plugin->new($args));
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

=option  sign_types ARRAY
=default sign_types 'SOAP-ENV:Body'
[1.08] specify the types of elements which need to be signed.  If you
have more elements of the same type, they will all get signed.
=cut

sub signature(%)
{   my ($self, %args) = @_;
    my $schema = $args{schema} || $self->schema;

    $args{sign_types} ||= ['SOAP-ENV:Body', 'env12:Body'];
    $args{sign_put}   ||= 'wsse:SecurityHeaderType';
    $args{sign_when}  ||= ['SOAP-ENV:Envelope', 'env12:Envelope'];

    my $sig    = $self->_start('XML::Compile::WSS::Signature', \%args);
    $sig;
}

#--------------------------------------
# [1.0] Expired interface
sub wsseBasicAuth($$$@)
{   my ($self, $username, $password, $pwtype, %args) = @_;
    # use XML::Compile::WSS::BasicAuth!!!  This method will be removed!

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
    # use XML::Compile::WSS::Timestamp!!!  This method will be removed!

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
