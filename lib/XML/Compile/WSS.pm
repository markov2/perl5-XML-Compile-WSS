use warnings;
use strict;

package XML::Compile::WSS;

use Log::Report 'xml-compile-wss';

use XML::Compile::WSS::Util qw/:wss11 UTP11_PDIGEST UTP11_PTEXT/;
use XML::Compile::Util      qw/SCHEMA2001/;
use XML::Compile::C14N;

use File::Basename          qw/dirname/;
use Digest::SHA1            qw/sha1_base64/;
use Encode                  qw/encode/;
use MIME::Base64            qw/encode_base64/;
use POSIX                   qw/strftime/;

my @prefixes11 = 
 ( wss   => WSS_11,  wsu    => WSU_10,    wsse  => WSSE_10
 , ds    => DSIG_NS, dsig11 => DSIG11_NS, dsigm => DSIG_MORE_NS
 , xenc  => XENC_NS, ghc    => GHC_NS,    dsp   => DSP_NS
 );

my %versions =
  ( '1.1' => {xsddir => 'wss11', prefixes => \@prefixes11}
  );

=chapter NAME
XML::Compile::WSS - OASIS Web Services Security

=chapter SYNOPSIS

 my $schema = XML::Compile::Cache->new(...);
 my $wss    = XML::Compile::WSS->new(version => '1.1'
   , schema => $schema);
 
 use XML::Compile::WSS::Util qw/:wss11 :utp11/;
 my $secPlain = $wss->wsseBasicAuth($username, $password, UTP11_TEXT);

 my $nonce     = 'some random string' ;
 my $created   = time();   # now (=default), or any pre-formatted date
 my $secDigest = $wss->wsseBasicAuth($username, $password, UTP11_PDIGEST
    , nonce => $nonce, created => $now, wsu_Id => 'foo');

 my $expires   = $created + 5 * 60;  # or any pre-formatted date
 my $sec_Time  = $wss->wsseTimestamp($created, $expires, wsu_Id => 'biz');

=chapter DESCRIPTION
The Web Services Security working group of W3C develops a set of
standards which add signatures and encryption to XML.

In its current status, this module supports processing (reading and
writing) of the XML meta-data involved, however there is no support for
in-file encryption or signature checking (yet).

The C<examples> directory included in the distribution of the module
contains examples how to use it. There even is an extended example how
to produce these structures (writing), but that is quite difficult where
the standard uses "any" elements everywhere.

=chapter METHODS

=section Constructors

=c_method new OPTIONS

=requires version '1.1'|MODULE
Explicitly state which version WSS needs to be produced.
You may use a version number. You may also use the MODULE
name, which is a namespace constant, provided via C<::Util>.
The only option is currently C<WSS11MODULE>.

=option  schema M<XML::Compile::Cache>
=default schema C<undef>
Add the WSS extension information to the provided schema.  If not used,
you have to call M<loadSchemas()> before compiling readers and writers.
=cut

sub new(@) { my $class = shift; (bless {}, $class)->init( {@_} ) }
sub init($)
{   my ($self, $args) = @_;
    my $version = $args->{version}
        or error __x"explicit wss_version required";
    trace "initializing wss $version";

    $version = '1.1'
        if $version eq WSS11MODULE;

    $versions{$version}
        or error __x"unknown wss version {v}, pick from {vs}"
             , v => $version, vs => [keys %versions];
    $self->{XCW_version} = $version;

    $self->loadSchemas($args->{schema})
        if $args->{schema};

    $self;
}

#-----------
=section Attributes

=method version
Returns the version number.
=method schema
=cut

sub version() {shift->{XCW_version}}
sub schema()  {shift->{XCW_schema}}

#-----------
=section Simplifications
=cut

# Some elements are allowed to have an Id attribute from the wsu
# schema, regardless of what the actual schema documents say.  So an
# attribute "wsu_Id" should get interpreted as such, if the writer
# has registered this hook.
sub _hook_WSU_ID
{   my ($doc, $values, $path, $tag, $r) = @_ ;
    my $id = delete $values->{wsu_Id};  # remove first, to avoid $r complaining
    my $node = $r->($doc, $values);
    if($id)
    {   $node->setNamespace(WSU_10, 'wsu', 0);
        $node->setAttributeNS(WSU_10, 'Id' => $id);
    }
    $node;
}

sub _datetime($)
{   my $time = shift;
    return $time if !$time || $time =~ m/[^0-9.]/;

    my $subsec = $time =~ /(\.[0-9]+)/ ? $1 : '';
    strftime "%Y-%m-%dT%H:%M:%S${subsec}Z", gmtime $time;
}

=method wsseTimestamp CREATED, EXPIRES, OPTIONS
CREATED and EXPIRES are timestamps: either some STRING (any format is
allowed by the spec, so hard to check automatically) or a NUMERIC
which is converted to ISO dateTime format for you.

This method does I<not> support adding a "ValueType" attribute to any
of the elements.
See a working example in F<examples/usertoken/with_help_digest.pl>.

=option  wsu_Id LABEL
=default wsu_Id undef
Adds a C<wsu:Id> attribute to the C<UsernameToken>, namely

   <wsse:UsernameToken wsu:Id="LABEL">

=example how to use wsseTimestamp
   my $created = time();
   my $expires = '2019-08-17T12:07:26Z';
   my $expires = $created + 300;  # alternative: + 5 minutes
   my $node = $wss->wsseTimestamp($created, $expires, wsu_Id => 'label');

produces

   <wsu:Timestamp wsu:Id="label">
     <wsu:Created>2012-08-17T12:02:26Z</wsu:Created>
     <wsu:Expires>2019-08-17T12:07:26Z</wsu:Expires>
   </wsu:Timestamp>

=cut

sub wsseTimestamp($$%)
{   my ($self, $created, $expires, %opts) = @_ ;

    my $schema   = $self->schema or panic;
    my $timestamptype = $schema->findName('wsu:Timestamp') ;
    my $doc      = XML::LibXML::Document->new('1.0', 'UTF-8');

    my $tsWriter = $schema->writer($timestamptype, include_namespaces => 1,
      , hook => {type => 'wsu:TimestampType', replace => \&_hook_WSU_ID} );

    my $tsToken  = $tsWriter->($doc, {wsu_Id => $opts{wsu_Id}
      , wsu_Created => _datetime($created)
      , wsu_Expires => _datetime($expires)});

    +{$timestamptype => $tsToken};
}

=method wsseBasicAuth USERNAME, PASSWORD, [PWTYPE, OPTIONS]
Many SOAP applications require a username/password authentication, like
HTTP's basic authentication. See F<examples/usertoken/manually.pl> for
an example how to construct this by hand for any possible requirement.
This method, however, offers a simplification for the usual case.  See
also working examples in F<examples/usertoken/with_help.pl> and
F<examples/usertoken/with_help_digest.pl>.

The optional PWTYPE parameter contains either the UTP11_PTEXT (default)
or UTP11_PDIGEST constant. The C<PTEXT> is the plain-text version of the
PASSWORD.

If PTWTYPE IS C<UTP11_PDIGEST>, the plain-text password will be
encrypted with SHA1.  The OPTIONS can be used to salt the digest
with "nonce" and/or "created" information before the encryption.

=option  created STRING|TIME
=default created undef
An extra "created" child element will be added.  The specification
allows a free-format STRING.  If you pass a number, it will get converted
into the standard iso dateTime format automatically.

  <wsse:UsernameToken>
     ...
     <wsu:Created>$created</wsu:Created>

There is no mechanism for adding a C<ValueType> attribute to this element.
The time string will be prepended to the password before the digest
is computed.

=option  nonce STRING
=default nonce undef

This will cause an extra child to be added to the C<UsernameToken>, namely

  <wsse:Nonce>$enc</wsse:Nonce>

where C<$enc> is the base64-encoding of the STRING.  The STRING will
be prepended to the password (and to any "created" information) before
the digest is computed.

=option  wsu_Id STRING
=default wsu_Id undef
Adds a C<wsu:Id> attribute to the created element.

=example how to use wsseBasicAuth
  my $call     = $wsdl->compileClient($operation);
  my $security = $wss->wsseBasicAuth($username, $password);

  my ($answer, $trace) = $call->
    ( wsse_Security => $security
    , %payload
    );

  use XML::Compiles::WSS::Util ':utp11';
  my $sec = $wss->wsseBasicAuth($user, $password, UTP11_PTEXT);

  my $sec = $wss->wsseBasicAuth($user, $password, UTP11_PDIGEST
     , created => time());
=cut

sub wsseBasicAuth($$;$%)
{   my ($self, $username, $password, $type, %opts) = @_;
    $type    ||= UTP11_PTEXT;
    my $schema = $self->schema or panic;
    my $doc    = XML::LibXML::Document->new('1.0', 'UTF-8');

    # The spec says we include "created" and "nonce" nodes if they're present.
    my @additional;
    my $nonce = $opts{nonce} || '';
    if($nonce)
    {   my $noncetype = $schema->findName('wsse:Nonce') ;
        my $noncenode = $schema->writer($noncetype, include_namespaces => 0)
            ->($doc, {_ => encode_base64($nonce)});
        push @additional, $noncetype => $noncenode;
    }

    my $created = $opts{created} || '';
    if($created)
    {   my $createdtype = $schema->findName('wsu:Created' ) ;
        # If _datetime changes $created into something different,
        # _that_ is what's going to need to be put into the
        # digest (if there's a digest).
        $created = _datetime($created) ;
        my $cnode = $schema->writer($createdtype, include_namespaces => 1)
            ->($doc, {_ => $created } );
        push @additional, $createdtype => $cnode;
    }

    if($type eq UTP11_PDIGEST)
    {   $password = sha1_base64(encode utf8 => "$nonce$created$password").'=';
    }

    my $pwtype = $schema->findName('wsse:Password');
    my $pwnode = $schema->writer($pwtype, include_namespaces => 0)
        ->($doc, {_ => $password, Type => $type});
    push @additional, $pwtype => $pwnode;

    # UsernameToken is allowed to have an "Id" attribute from the wsu schema.
    # We set up the writer with a hook to add that particular attribute.
    my $untype   = $schema->findName('wsse:UsernameToken');
    my $unwriter = $schema->writer($untype, include_namespaces => 1,
      , hook => {type => 'wsse:UsernameTokenType', replace => \&_hook_WSU_ID});

    my $token   = $unwriter->($doc
      , {wsu_Id => $opts{wsu_Id}, wsse_Username => $username, @additional});

    +{ $untype => $token };
}

#-----------
=section Internals

=method loadSchemas SCHEMA
SCHEMA must extend M<XML::Compile::Cache>.

The SCHEMA settings will may changed a little. For one, the
C<allow_undeclared> flag will be set. Also, C<any_element> will be set to
'ATTEMPT' and C<mixed_elements> to 'STRUCTURAL'.

=cut

sub loadSchemas($)
{   my ($self, $schema) = @_;

    $schema->isa('XML::Compile::Cache')
        or error __x"loadSchemas() requires a XML::Compile::Cache object";
    $self->{XCW_schema} = $schema;

    my $version = $self->version;
    my $def = $versions{$version};

    my $prefixes = $def->{prefixes};
    $schema->prefixes(@$prefixes);
    {   local $" = ',';
        $schema->addKeyRewrite("PREFIXED(@$prefixes)");
    }

    (my $xsddir = __FILE__) =~ s! \.pm$ !/$def->{xsddir}!x;
    my @xsd = glob "$xsddir/*.xsd";

    trace "loading wss for $version";

    $schema->importDefinitions
       ( \@xsd

         # Missing from wss-secext-1.1.xsd (schema BUG)  Gladly, all
         # provided schemas have element_form qualified.
       , element_form_default => 'qualified'
       );

    # Another schema bug; attribute wsu:Id not declared qualified
    my ($wsu, $xsd) = (WSU_10, SCHEMA2001);
    $schema->importDefinitions( <<__PATCH );
<schema
  xmlns="$xsd"
  targetNamespace="$wsu"
  elementFormDefault="qualified"
  attributeFormDefault="qualified">
    <attribute name="Id" type="ID" />
</schema>
__PATCH

    XML::Compile::C14N->new(version => 1.1, schema => $schema);
    $schema->allowUndeclared(1);
    $schema->addCompileOptions(RW => mixed_elements => 'STRUCTURAL');
    $schema->anyElement('ATTEMPT');

    $self;
}

=section SEE ALSO
=over 4

=item XML Security Generic Hybrid Ciphers
F<http://www.w3.org/TR/2011/CR-xmlsec-generic-hybrid-20110303/>, 3 March 2011

=item XML Signature Properties
F<http://www.w3.org/TR/2011/CR-xmldsig-properties-20110303/>, 3 March 2011

=item XML Signature Syntax and Processing Version 1.1
F<http://www.w3.org/TR/2011/CR-xmldsig-core1-20110303/>, 3 March 2011

=item SOAP message security
F<http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0.pdf>, March 2004

=item XML Signature Syntax and Processing (Second Edition)
F<http://www.w3.org/TR/2008/REC-xmldsig-core-20080610/>, 10 June 2008

=item RFC4050 Using the ECDSA for XML Digital Signatures
F<http://www.ietf.org/rfc/rfc4050.txt>, april 2005

=item RFC4051 Additional XML Security Uniform Resource Identifiers (URIs)
F<http://www.ietf.org/rfc/rfc4051.txt>, april 2005

=item XML Encryption Syntax and Processing
F<http://www.w3.org/TR/2002/REC-xmlenc-core-20021210/>, 10 December 2002

=back
=cut

1;
