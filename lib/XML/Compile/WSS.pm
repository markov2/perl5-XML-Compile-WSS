use warnings;
use strict;

package XML::Compile::WSS;

use Log::Report 'xml-compile-wss';

use XML::Compile::WSS::Util qw/:wss11 UTP11_PDIGEST UTP11_PTEXT/;
use XML::Compile::Util      qw/SCHEMA2001/;
use XML::Compile::C14N;
use XML::Compile::Schema::BuiltInTypes qw/builtin_type_info/;

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

 # This modules van be used "stand-alone" ...
 my $schema = XML::Compile::Cache->new(...);
 my $auth   = XML::Compile::WSS::BasicAuth->new
   (schema => $schema, username => $user, ...);

 # ... or as SOAP slave (strict order of object creation!)
 my $wss    = XML::Compile::SOAP::WSS->new;
 my $wsdl   = XML::Compile::WSDL11->new($wsdlfn);
 my $auth   = $wss->basicAuth(username => $user, ...);
 
=chapter DESCRIPTION
The Web Services Security working group of W3C develops a set of
standards which add signatures and encryption to XML.

In its current status, this module implements features in the C<Security>
header.  One header may contain more than one of these:
=over 4
=item * timestamps in M<XML::Compile::WSS::Timestamp>
=item * username/password authentication in M<XML::Compile::WSS::BasicAuth>
=item * signing of the body in M<XML::Compile::WSS::Signature>
=item * encryption is not yet supported.  Please hire me to get it implemented.
=back

You will certainly need the constants from M<XML::Compile::WSS::Util>.
Besides, when you want to use Security with SOAP, then use
M<XML::Compile::SOAP::WSS>.

=chapter METHODS

=section Constructors

=c_method new OPTIONS

=requires wss_version '1.1'|MODULE
[1.0] Explicitly state which version WSS needs to be produced.
You may use a version number. You may also use the MODULE
name, which is a namespace constant, provided via C<::Util>.
The only option is currently C<WSS11MODULE>.

=option  version STRING
=default version C<undef>
Alternative for C<wss_version>, but not always as clear.

=option  schema an M<XML::Compile::Cache> object
=default schema C<undef>
Add the WSS extension information to the provided schema.  If not used,
you have to call M<loadSchemas()> before compiling readers and writers.
=cut

sub new(@)
{   my $class = shift;
    my $args  = @_==1 ? shift : {@_};
    (bless {}, $class)->init($args)->prepare;
}

my $schema;
sub init($)
{   my ($self, $args) = @_;
    my $version = $args->{wss_version} || $args->{version}
        or error __x"explicit wss_version required";
    trace "initializing wss $version";

    $version = '1.1'
        if $version eq WSS11MODULE;

    $versions{$version}
        or error __x"unknown wss version {v}, pick from {vs}"
             , v => $version, vs => [keys %versions];
    $self->{XCW_version} = $version;

    if($schema = $args->{schema})
    {   my $class = ref $self;    # it is class, not object, related!
        $class->loadSchemas($args->{schema}, $version);
    }
    $self;
}

sub prepare($)
{   my ($self, $args) = @_;
    $self->prepareWriting($schema);
    $self->prepareReading($schema);
    $self;
}
sub prepareWriting($) { shift }
sub prepareReading($) { shift }

#-----------
=section Attributes

=method version
Returns the version number.
=method schema
=cut

sub version() {shift->{XCW_version}}
sub schema()  {$schema}

#-----------

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

#-----------
=section Helpers

=method dateTime TIME|STRING|HASH
Returns a structure which can be used as timestamp, for instance in
C<Created> and C<Expires> fields.  This helper function will help you
use these timestamp fields correctly.

The WSU10 specification defines a free format timestamp.  Of course,
that is very impractical.  Typically a "design by committee" decission.
Also, the standard does not describe the ValueType field, which is often
used to cover this design mistake.
=example

  # Both will get ValueType="$xsd/dateTime"
  Created => time()                 # will get formatted
  Created => '2012-10-14T22:26:21Z' # autodected

  # Explicit formatting
  Created => { _ => 'this Christmas'
             , ValueType => 'http://per6.org/releasedates'
             };

  # No ValueType added
  Created => 'this Christmas'
=cut

# wsu had "allow anything" date fields, not type dateTime
sub dateTime($)
{   my ($self, $time) = @_;
    return $time if !defined $time || ref $time;

    my $dateTime = builtin_type_info 'dateTime';
    if($time !~ m/[^0-9.]/) { $time = $dateTime->{format}->($time) }
    elsif($dateTime->{check}->($time)) {}
    else {return $time}

     +{ _ => $time
      , ValueType => SCHEMA2001.'/dateTime'
      };
}

#-----------
=section Internals

=c_method loadSchemas SCHEMA, VERSION
SCHEMA must extend M<XML::Compile::Cache>.

The SCHEMA settings will may changed a little. For one, the
C<allow_undeclared> flag will be set. Also, C<any_element> will be set to
'ATTEMPT' and C<mixed_elements> to 'STRUCTURAL'.

=cut

my $schema_loaded = 0;
sub loadSchemas($$)
{   my ($class, $schema, $version) = @_;
    return $class if $schema_loaded++;

    $schema->isa('XML::Compile::Cache')
        or error __x"loadSchemas() requires a XML::Compile::Cache object";

    my $def      = $versions{$version};
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
    # Besides, ValueType is often used on timestamps, which are declared
    # as free-format fields (@*!&$#!&^ design committees!)
    my ($wsu, $xsd) = (WSU_10, SCHEMA2001);
    $schema->importDefinitions( <<__PATCH );
<schema
  xmlns="$xsd"
  xmlns:wsu="$wsu"
  targetNamespace="$wsu"
  elementFormDefault="qualified"
  attributeFormDefault="unqualified">
    <attribute name="Id" type="ID" form="qualified" />

    <complexType name="AttributedDateTime">
      <simpleContent>
        <extension base="string">
          <attribute name="ValueType" type="anyURI" />
          <attributeGroup ref="wsu:commonAtts"/>
        </extension>
      </simpleContent>
   </complexType>

</schema>
__PATCH

    XML::Compile::C14N->new(version => '1.1', schema => $schema);
    $schema->allowUndeclared(1);
    $schema->addCompileOptions(RW => mixed_elements => 'STRUCTURAL');
    $schema->anyElement('ATTEMPT');

    # If we find a wsse_Security which points to a WSS or an ARRAY of
    # WSS, we run all of them.
    my $create_security =
     +{ type   => 'wsse:SecurityHeaderType'
      , before => sub {
        my ($doc, $from, $path) = @_;
        my $data = {};
        if( UNIVERSAL::isa($from, 'XML::Compile::SOAP::WSS')
         || UNIVERSAL::isa($from, __PACKAGE__))
             { $from->create($doc, $data) }
        elsif(ref $from eq 'ARRAY')
             { $_->create($doc, $data) for @$from }
        else { $data = $from }

        $data;
    }};

    $schema->declare(WRITER => 'wsse:Security', hooks => $create_security);
    $schema;
}

#---------------------------

=chapter DETAILS

=section Specifications

A huge number of specifications act in this field.  Every self respecting
company has contributed its own implementation into the field.  A lot of
this is B<not supported>, but the list of constants should be complete
in M<XML::Compile::WSS::Util>.

=over 4

=item * XML Security Generic Hybrid Ciphers
F<http://www.w3.org/TR/2011/CR-xmlsec-generic-hybrid-20110303/>, 3 March 2011

=item * XML Signature Properties
F<http://www.w3.org/TR/2011/CR-xmldsig-properties-20110303/>, 3 March 2011

=item * XML Signature Syntax and Processing Version 1.1
F<http://www.w3.org/TR/2011/CR-xmldsig-core1-20110303/>, 3 March 2011

=item * SOAP message security
F<http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0.pdf>, March 2004

=item * XML Signature Syntax and Processing (Second Edition)
F<http://www.w3.org/TR/2008/REC-xmldsig-core-20080610/>, 10 June 2008

=item * RFC4050 Using the ECDSA for XML Digital Signatures
F<http://www.ietf.org/rfc/rfc4050.txt>, april 2005

=item * RFC4051 Additional XML Security Uniform Resource Identifiers (URIs)
F<http://www.ietf.org/rfc/rfc4051.txt>, april 2005

=item * XML Encryption Syntax and Processing
F<http://www.w3.org/TR/2002/REC-xmlenc-core-20021210/>, 10 December 2002

=back
=cut

1;
