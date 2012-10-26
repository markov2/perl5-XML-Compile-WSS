use warnings;
use strict;

package XML::Compile::WSS::Signature;
use base 'XML::Compile::WSS';

use Log::Report 'xml-compile-wss';

use XML::Compile::WSS::Util   qw/:wss11 :dsig :xtp10 :wsm10/;
use XML::Compile::C14N::Util  qw/:c14n/;

use XML::LibXML     ();
use HTTP::Response  ();
use MIME::Base64    qw/decode_base64 encode_base64/;
use File::Slurp     qw/read_file/;
use Digest          ();
use Scalar::Util    qw/blessed/;

my $unique = $$.time;

use Data::Dumper;
$Data::Dumper::Indent    = 1;
$Data::Dumper::Quotekeys = 0;

my %canon =          #comment  excl
  ( &C14N_v10_NO_COMM  => [ 0, 0 ]
  , &C14N_v10_COMMENTS => [ 1, 0 ]
  , &C14N_v11_NO_COMM  => [ 0, 0 ]
  , &C14N_v11_COMMENTS => [ 1, 0 ]
  , &C14N_EXC_NO_COMM  => [ 0, 1 ]
  , &C14N_EXC_COMMENTS => [ 1, 1 ]
  );

my %keywraps =
 ( &XTP10_X509    => 'PUBLIC KEY'
 , &XTP10_X509PKI => 'RSA PUBLIC KEY'
 , &XTP10_X509v3  => 'CERTIFICATE'
 );

my ($digest_algorithm, $sign_algorithm);
{  my ($signs, $sigmns) = (DSIG_NS, DSIG_MORE_NS);
   # the digest algorithms can be distiguish by pure lowercase, no dash.
   $digest_algorithm = qr/^(?:$signs|$sigmns)([a-z0-9]+)$/;
   $sign_algorithm   = qr/^(?:$signs|$sigmns)([a-z0-9]+)\-([a-z0-9]+)$/;
}

=chapter NAME
XML::Compile::WSS::Signature - WSS in CICS-TS style

=chapter SYNOPSIS

B<WARNING: under development!>

 # You may need a few of these
 use XML::Compile::WSS::Util  qw/:dsig/;
 use XML::Compile::C14N::Util qw/:c14n/;

 # This modules van be used "stand-alone" ...
 my $schema = XML::Compile::Cache->new(...);
 my $sig    = XML::Compile::WSS::Signature->new
   (sign_method => DSGIG_RSA_SHA1, ...);

 # ... or as SOAP slave (strict order of object creation!)
 my $wss    = XML::Compile::SOAP::WSS->new;
 my $wsdl   = XML::Compile::WSDL11->new($wsdlfn);
 my $sig    = $wss->signature(sign_method => ...);

=chapter DESCRIPTION
The generic Web Service Security protocol is implemented by the super
class M<XML::Compile::WSS>.  This extension implements cypto signatures.

One or more elements of the document can be selected to be signed (with
M<signElement()>)  They are canonalized (serialized in a well-described
way) and then digested (usually via SHA1).  The digest is put in a
C<SignedInfo> component of the C<Signature> feature in the C<Security>
header.  When all digests are in place, the whole SignedInfo structure

=section Limitations
Many companies have their own use of the pile of standards for this
feature.  Some of the resulting limitations are known by the author:

=over 4
=item * digests
Only digest algorithms which are provided via the M<Digest> module are
supported for the elements to be signed.
=item * signatures
Only a limited subset of signing (algoritm, hash) combinations are
supported.  Lower on this page, you find details about each of the
provided signing implementations.
=back

=chapter METHODS

=section Constructors

=c_method new OPTIONS

=default wss_version  '1.1'

=option  digest_method DIGEST
=default digest_method DSIG_SHA1
The algorithm used to sign the body digest, when sending.  The digest
name is an ugly constant which has a nice C<DSIG_*> alias defined
in M<XML::Compile::WSS::Util>.

=option  canon_method CANON
=default canon_method C14N_EXC_NO_COMM
The algorithm to be used for canonicalization of some component.
These constants are pre-defined with nice C<C14N_*> names in
M<XML::Compile::C14N::Util>.

=option  prefix_list ARRAY
=default prefix_list [ds wsu xenc SOAP-ENV]
Used for canonicalization.

=option  sign_method SIGN
=default sign_method DSIG_RSA_SHA1
The choices here are explained below, in the L</DETAILS> section of
this manual page.

=option  private_key OBJECT|STRING|FILENAME
=default private_key C<undef>
The exact features of this option depend on the sign_method.  Usually,
you can specify an OBJECT which contains the key, or STRING or FILENAME
to create such an object.

=option  public_key_type KEYTYPE
=default public_key_type <depends on sign_method>
The KEYTYPE must be specified in the SignedInfo.  It depends on the
C<sign_method> which default is taken.

=option  public_key  OBJECT|STRING|FILENAME
=default public_key  <depends on sign_method>
In some cases, the public key can be derived from the private key.

=option  public_key_id STRING
=default public_key_id 'public-key'

=option  publish_pubkey 'INCLUDE_BY_REF'|CODE
=default publish_pubkey 'INCLUDE_BY_REF'
How to publish the public key.  The C<INCLUDE_BY_REF> constant (currently
the only one supported) will add the key as BinarySecurityToken in the message,
plus a keyinfo structure with a reference to that token.

=option  remote_pubkey OBJECT|STRING|FILENAME
=default remote_pubkey C<undef>
To defend against man-in-the-middle attacks, you need to specify the
server's public key.  When specified, that key will be used to verify
the signature, not the one listed in the XML response.

Only when this C<remote_pubkey> is specified, we will require the
signature.  Otherwise, the check of the signature will only be performed
when a Signature is available in the Security header.

=option  remote_pubkey_type KEYTYPE
=default remote_pubkey_type C<XTP10_X509>
Used when C<remote_pubkey> is a STRING or FILENAME.

=option  remote_pubkey_encoding ENCODING
=default remote_pubkey_encoding C<undef>
Used when C<remote_pubkey> is a STRING or FILENAME.  Usually WSM10_BASE64,
to indicate that the key is in base64 encoding.  When not defined, the
key is in binary format.

=option  remote_sign_method SIGNMETHOD
=default remote_sign_method C<DSIG_RSA_SHA1>
Used when the C<remote_pubkey> is specified.
=cut

sub init($)
{   my ($self, $args) = @_;
    $args->{wss_version} ||= '1.1';

    $self->SUPER::init($args);

    # Run digest to initialize modules (and detect what is not installed)
    # Usually client and server use the same algorithms
    my $digest = $self->{XCWS_digmeth}  = $args->{digest_method} || DSIG_SHA1;
    $self->digest($digest, \"test digest");

    my $sign = $self->{XCWS_signmeth} = $args->{sign_method} || DSIG_RSA_SHA1;
    $self->{XCWS_signer}     = $self->_create_signer($sign, $args);

    $self->{XCWS_pubkey_uri} = $args->{public_key_id } || 'public-key';
    $self->{XCWS_publ_key}   = $args->{publish_pubkey} || 'INCLUDE_BY_REF';

    $self->{XCWS_canonmeth}  = $args->{canon_method}   || C14N_EXC_NO_COMM;
    $self->{XCWS_prefixlist} = $args->{prefix_list}
                            || [ qw/ds wsu xenc SOAP-ENV/ ];
    $self->{XCWS_to_check}   = {};
    $self->{XCWS_checker}    = $self->_create_remote_pubkey($args);
    $self;
}

#-----------------------------

=section Helpers

=subsection Digest

=method defaultDigestMethod
Returns the default DIGEST constant, as set with M<new(digest_method)>.

This must be a full constant name, as provided by M<XML::Compile::WSS::Util>.
They are listed under export tags C<:dsig> and C<:dsigm>.
=cut

sub defaultDigestMethod() { shift->{XCWS_digmeth} }

=method digest DIGEST, TEXTREF
Digest the text (passed as TEXTREF for reasons of performance) into
a binary string.
=cut

sub digest($$)
{   my ($self, $method, $text) = @_;
    $method =~ $digest_algorithm
        or error __x"digest {name} is not a correct constant";
    my $algo = uc $1;

    my $digest = try { Digest->new($algo)->add($$text)->digest };
    $@ and error __x"cannot use digest method {short}, constant {name}: {err}"
      , short => $algo, name => $method, err => $@->wasFatal;

    $digest;
}

sub _digest_elem_check($$)
{   my ($self, $elem, $ref) = @_;
    my $transf   = $ref->{ds_Transforms}{ds_Transform}[0]; # only 1 transform
    my ($inclns, $preflist) = %{$transf->{cho_any}[0]};    # only 1 kv pair
    my $elem_c14n = $self
        ->_apply_canon($transf->{Algorithm}, $preflist->{PrefixList})
        ->($elem);

    my $digmeth = $ref->{ds_DigestMethod}{Algorithm} || '(none)';
    $self->digest($digmeth, \$elem_c14n) eq $ref->{ds_DigestValue};
}
#-----------------------------

=subsection Canonicalization

=method defaultCanonMethod
Returns the default Canonicalization method as constant.

=method canon [CANON]
Returns information about canonicalization method CANON.  By default
the algoritm of M<defaultCanonMethod()>.

=method prefixList
Returns an ARRAY with the prefixes to be used in canonicalization.
=cut

sub defaultCanonMethod() {shift->{XCWS_canonmeth}}
sub canon($) {my $r = $canon{$_[1] || shift->defaultCanonMethod}; $r ? @$r : ()}
sub prefixList() {shift->{XCWS_prefixlist} || []}

# XML::Compile has to trick with prefixes, because XML::LibXML does not
# permit the creation of nodes with explicit prefix, only by namespace.
# The next can be slow and is ugly, Sorry.  MO
sub _repair_xml($$)
{   my ($self, $xc_out_dom) = @_;

    # only doc element does charsets correctly
    my $doc    = $xc_out_dom->ownerDocument;

    # building bottom up: be sure we have all namespaces which may be
    # declared later, on higher in the hierarchy.
    my $env    = $doc->createElement('Dummy');
    my $prefixes = $self->schema->prefixes;
    $env->setNamespace($_->{uri}, $_->{prefix}, 0)
        for values %$prefixes;

    # reparse tree
    $env->addChild($xc_out_dom);
    my $fixed_dom = XML::LibXML->load_xml(string => $env->toString(0));
    my $new_out   = ($fixed_dom->documentElement->childNodes)[0];
    $doc->importNode($new_out);
    $new_out;
}

sub _apply_canon(;$$)
{   my ($self, $algo, $prefixlist) = @_;
    $algo       ||= $self->defaultCanonMethod;
    $prefixlist ||= $self->prefixList;

    my ($with_comments, $with_exc) = $self->canon($algo);
    defined $with_comments
        or error __x"unsupported canonicalization method {name}", name => $algo;

    my $serialize = $with_exc ? 'toStringEC14N' : 'toStringC14N';

    # Don't know what $path and $context are expected to be
    my $path      = 0;

    sub {
        my ($node) = @_;
        my $repaired = $self->_repair_xml($node);
        my $context = XML::LibXML::XPathContext->new($repaired);
        $repaired->$serialize($with_comments, undef, $context, $prefixlist);
    };
}

#-----------------------------

=subsection KeyInfo
=cut

sub _create_keyinfo()
{   my $self  = shift;
    my $pubpk = $self->{XCWS_publ_key};
    return $pubpk if ref $pubpk eq 'CODE';
 
    $pubpk eq 'INCLUDE_BY_REF'
        or error __x"publish_pubkey either CODE or 'INCLUDE_BY_REF'";

    my $token   = $self->{XCWS_pubkey_base64};
    my $uri     = $self->{XCWS_pubkey_uri};
    my $keytype = $self->{XCWS_pubkey_t};

    my $schema  = $self->schema;
    $schema->prefixFor(WSU_10);

    my $krt = $schema->findName('wsse:Reference');
    my $krw = $schema->writer($krt, include_namespaces => 0);

    my $kit = $schema->findName('wsse:SecurityTokenReference');
    my $kiw = $schema->writer($kit, include_namespaces => 0);

    my $ctt = $schema->findName('wsse:BinarySecurityToken');
    my $ctw = $schema->writer($ctt, include_namespaces => 0);

    sub ($$) {
       my ($doc, $sec) = @_;
       my $kr  = $krw->($doc, {URI => $uri, ValueType => $keytype});
       my $ki  = $kiw->($doc, {cho_any => {$krt => $kr}});
       my %keyinfo;
       push @{$keyinfo{cho_ds_KeyName}}, {$kit => $ki};

       my $ct  = $ctw->($doc,
         { EncodingType => WSM10_BASE64
         , ValueType    => $keytype
         , _            => $token        # already base64
         });
       $ct->setNamespace(WSU_10, 'wsu', 0);
       $ct->setAttributeNS(WSU_10, 'Id', $uri);
       $sec->{$ctt} = $ct;
       \%keyinfo;
    };
}

#-----------------------------
=subsection Signing

=method signMethod

=method checker
When the remote public key is specified explicitly, this will return
the code-reference to check it received SignedInfo.
=cut

sub signMethod() {shift->{XCWS_signmeth}}
sub checker()    {shift->{XCWS_checker}}

sub _create_signer($$)
{   my ($self, $method, $args) = @_;
    $method =~ $sign_algorithm
        or error __x"method {name} is not a sign algorithm";
    my ($algo, $hashing) = (uc $1, uc $2);

    if($algo eq 'RSA') { $self->_setup_hashing_rsa($hashing, $args) }
    else
    {   error __x"signing algorithm {name} not (yet) unsupported", name => $hashing;
    }

}

sub _checker_from_token($$)
{   my ($self, $method, $token) = @_;
    $method =~ $sign_algorithm
        or error __x"method {name} is not a sign algorithm", name => $method;
    my ($algo, $hashing) = (uc $1, uc $2);

        $algo eq 'RSA' ? $self->_checker_from_token_rsa($hashing, $token)
      : error __x"signing algorithm {name} not (yet) unsupported"
          , name => $hashing;
}

sub _create_remote_pubkey($)
{   my ($self, $args) = @_;
    my $key = $args->{remote_pubkey} or return;

    if(ref $key)
    {   blessed $key && $key->isa('Crypt::OpenSSL::RSA')
            or error __x"server public key object type not supported";
        return $self->_check_rsa($key);
    }

    if($key =~ m/\.(?:der|pub)$/i)
    {   my $pubkey = Crypt::OpenSSL::RSA->new_public_key(scalar read_file $key);
        return $self->_check_rsa($pubkey);
    }

    # construct a token as if from the server, less to implement per algo
    my $method = $args->{remote_sign_method} || DSIG_RSA_SHA1;
    my %token =
      ( ValueType    => ($args->{remote_pubkey_type} || XTP10_X509)
      , EncodingType => $args->{remote_pubkey_encoding}
      , _            => $key
      );

    $self->_checker_from_token($method, \%token);
}

=method signElement NODE, OPTIONS
Add an element to be the list of NODEs to be signed.  For instance,
the SOAP message will register the C<SOAP-ENV:Body> here.

=option  id UNIQUEID
=default id C<unique>
Each element to be signed needs a C<wsu:Id> to refer to.  If the NODE
does not have one, the specified UNIQUEID is taken.  If there is none
specified, one is generated.
=cut

sub signElement(%)
{   my ($self, $node, %args) = @_;
    my $wsuid = $node->getAttributeNS(WSU_10, 'Id');
    unless($wsuid)
    {   $wsuid = $args{id} || 'elem-'.$unique++;
        $node->setNamespace(WSU_10, 'wsu', 0);
        $node->setAttributeNS(WSU_10, 'Id', $wsuid);
    }
    push @{$self->{XCWS_to_sign}}, +{node => $node,  id => $wsuid};
    $node;
}

=method elementsToSign
Returns an ARRAY of all NODES which need to be signed.  This will
also reset the administration.
=cut

sub elementsToSign() { delete shift->{XCWS_to_sign} || [] }

=method checkElement ELEMENT
Register the ELEMENT to be checked for correct signature.
=cut

sub checkElement($%)
{   my ($self, $node, %args) = @_;
    my $id = $node->getAttributeNS(WSU_10, 'Id')
        or error "element to check {name} has no wsu:Id"
             , name => $node->nodeName;

    $self->{XCWS_to_check}{$id} = $node;
}

=method elementsToCheck
Returns a HASH with (wsu-id, node) pairs to be checked.  The administration
is reset with this action.
=cut

sub elementsToCheck()
{   my $self = shift;
    my $to_check = delete $self->{XCWS_to_check};
    $self->{XCWS_to_check} =  {};
    $to_check;
}

#-----------------------------
#### HELPERS

sub _get_sec_token($$)
{   my ($self, $sec, $sig) = @_;
    my $sec_tokens = $sig->{ds_KeyInfo}{cho_ds_KeyName}[0]
        ->{wsse_SecurityTokenReference}{cho_any}[0];
    my ($key_type, $key_data) = %$sec_tokens;
    $key_type eq 'wsse_Reference'
        or error __x"key-type {type} not yet supported", type => $key_type;
    my $key_uri    = $key_data->{URI} or panic;
    (my $key_id    = $key_uri) =~ s/^#//;
    my $token      = $sec->{wsse_BinarySecurityToken};

    $token->{wsu_Id} eq $key_id
        or error __x"token does not match reference";

    $token->{ValueType} eq $key_data->{ValueType}
        or error __x"token type {type1} does not match expected {type2}"
            , type1 => $token->{ValueType}, type2 => $key_data->{ValueType};
    $token;
}

sub prepareReading($)
{   my ($self, $schema) = @_;
    $self->SUPER::prepareReading($schema);

    my %security_tokens;   # the BinarySecurityToken keys, binary form

    $schema->declare(READER => 'ds:Signature',
      , hooks => {type => 'ds:SignedInfoType', after => 'XML_NODE'});

    $self->{XCWS_reader} = sub {
        my $sec  = shift;
#warn Dumper $sec;
        my $sig  = $sec->{ds_Signature};
        unless($sig)
        {   # When the signature is missing, we only die if we expect one
            $self->checker or return;
            error __x"requires signature block missing from remote";
        }

        my $info       = $sig->{ds_SignedInfo} || {};

        # Check signature on SignedInfo
        my $can_meth   = $info->{ds_CanonicalizationMethod};
        my $can_pref   = $can_meth->{c14n_InclusiveNamespaces}{PrefixList};
        my $si_canon   = $self->_apply_canon($can_meth->{Algorithm}, $can_pref)
            ->($info->{_XML_NODE});

        my $checker    = $self->checker;
        unless($checker)
        {   my $sig_meth = $info->{ds_SignatureMethod}{Algorithm};
            my $token    = $self->_get_sec_token($sec, $sig);
            $checker     = $self->_checker_from_token($sig_meth, $token);
        }
        $checker->(\$si_canon, $sig->{ds_SignatureValue}{_})
            or error __x"signature on SignedInfo incorrect";

        # Check digest of the elements
        my %references;
        foreach my $ref (@{$info->{ds_Reference}})
        {   my $uri = $ref->{URI};
            $references{$uri} = $ref;
        }

        my $check = $self->elementsToCheck;
#print "FOUND: ", Dumper \%references, $info, $check;
        foreach my $id (sort keys %$check)
        {   my $node = $check->{$id};
            my $ref  = delete $references{"#$id"}
                or error __x"cannot find digest info for {elem}", elem => $id;
            $self->_digest_elem_check($node, $ref)
                or warning __x"digest info of {elem} is wrong", elem => $id;
        }
    };

    $self;
}

sub check($)
{   my ($self, $data) = @_;
    $self->{XCWS_reader}->($data);
}

### BE WARNED: created nodes can only be used once!!! in XML::LibXML

sub _create_inclns($)
{   my ($self, $prefixes) = @_;
    $prefixes ||= [];
    my $schema  = $self->schema;
    my $type    = $schema->findName('c14n:InclusiveNamespaces');
    my $incns   = $schema->writer($type, include_namespaces => 0);

    ( $type, sub {$incns->($_[0], {PrefixList => $prefixes})} );
}

sub _fill_signed_info($$)
{   my ($self, $canon, $prefixes) = @_;
    my ($incns, $incns_make) = $self->_create_inclns($prefixes);
    my $canonical = $self->_apply_canon($canon, $prefixes);
    my $digest    = $self->defaultDigestMethod;
    my $signmeth  = $self->signMethod;

    sub {
        my ($doc, $parts) = @_;
        my $canon_method =
         +{ Algorithm => $canon
          , $incns    => $incns_make->($doc)
          };
    
        my @refs;
        foreach my $part (@$parts)
        {   my $digested  = $self->digest($digest,\$canonical->($part->{node}));
    
            my $transform =
              { Algorithm => $canon
              , cho_any => [ {$incns => $incns_make->($doc)} ]
              };
    
            push @refs,
             +{ URI             => '#'.$part->{id}
              , ds_Transforms   => { ds_Transform => [$transform] }
              , ds_DigestValue  => $digested
              , ds_DigestMethod => { Algorithm => $digest }
              };
        }
    
         +{ ds_CanonicalizationMethod => $canon_method
          , ds_Reference              => \@refs
          , ds_SignatureMethod        => { Algorithm => $signmeth }
          };
    };
}

sub prepareWriting($)
{   my ($self, $schema) = @_;
    $self->SUPER::prepareWriting($schema);
    return $self if $self->{XCWS_sign};
    my @elements_to_sign;

    my $settings  = $self->_create_keyinfo;
    my $si_canon  = $self->defaultCanonMethod;
    my $si_prefl  = $self->prefixList;

    my $fill_signed_info = $self->_fill_signed_info($si_canon, $si_prefl);
    my $canonical = $self->_apply_canon($si_canon, $si_prefl);
    my $sign      = $self->{XCWS_hasher};

    # encode by hand, because we need the signature immediately
    my $infow = $schema->writer('ds:SignedInfo');

    my $sigt  = $schema->findName('ds:Signature');
    my $sigw  = $schema->writer($sigt);

    $self->{XCWS_sign} = sub {
        my ($doc, $sec) = @_;
        return $sec if $sec->{$sigt};
        my $info      = $fill_signed_info->($doc, $self->elementsToSign);
        my $keyinfo   = $settings->($doc, $sec);
        my $info_node = $self->_repair_xml($infow->($doc, $info));
        my $signature = $sign->(\$canonical->($info_node));

        # The signature value is only known when the Info is ready,
        # but gladly they are produced in the same order.
        my %sig =
          ( ds_SignedInfo     => $info_node
          , ds_SignatureValue => {_ => $signature}
          , ds_KeyInfo        => $keyinfo
          );

        $sec->{$sigt}     = $sigw->($doc, \%sig);
        $sec;
    };
    $self;
}

sub create($$)
{   my ($self, $doc, $sec) = @_;
    # cannot do much yet, first the Body must be ready.
    $self->{XCWS_sec_hdr} = $sec;
    $self;
}

=method createSignature DOCUMENT
Must be called after all elements-to-be-signed have been created,
but before the SignedInfo object gets serialized.
=cut

sub createSignature($)
{   my ($self, $doc) = @_;
    $self->{XCWS_sign}->($doc, $self->{XCWS_sec_hdr});
}

#---------------------------
=chapter DETAILS

=section Signing, the generic part

The base of this whole security protocol is crypto-signing the messages,
so you will always need to specify some parameters for M<new()>.

  my $wss  = XML::Compile::WSS::Signature->new
    ( sign_method => DSIG_$algo
    , ...parameters for $algo...
    );

When the algorithm is known (see the next sections of this chapter),
then the parameters will be used to produce the CODE which will do the
signing.

=section Defend against man-in-the-middle

The signature can easily be spoofed with a man-in-the-middle attack,
unless you hard-code the remote's public key.

  my $wss  = XML::Compile::WSS::Signature->new
    ( ...
    , remote_sign_method     => DSIG_RSA_SHA1    # default
    , remote_pubkey_type     => XTP10_X509       # default
    , remote_pubkey_encoding => WSM10_BASE64
    , remote_pubkey          => $base64_enc_key_string
    );

  my $wss  = XML::Compile::WSS::Signature->new
    ( ...
    , remote_sign_method     => DSIG_RSA_SHA1    # default
    , remote_pubkey          => $key
      # $key is a Crypt::OpenSSL::RSA public key object
    );
   
=section Signing with RSA

=subsection Limitations

The signing algorithm uses M<Crypt::OpenSSL::RSA>.  According to its
manual-page, the current implementation is limited to 

=over 4
=item * sign_method

   DSIG_RSA_SHA1     DSIGM_RSA_MD5     DSIGM_RSA_SHA256
   DSIGM_RSA_SHA384  DSIGM_RSA_SHA512

It could support some RSA_RIPEMD160, however there is no official
constant for that in the standards.

=item * public_key_type

  XTP10_X509         XTP10_X509PKI

=back

=subsection Usages

Example:

  my $wss  = XML::Compile::WSS::Signature->new
     ( sign_method     => DSIG_RSA_SHA1
     , private_key     => $privkey
     , public_key_type => XTP10_X509       # default
     , public_key      => $pubkey          # default from $privkey
     , public_key_id   => 'public-key'     # default
     , publish_pubkey  => 'INCLUDE_BY_REF' # default
     );

=subsection Private key

You have to provide the private key. There are various ways to do that.
Valid values for C<$privkey> in above example:

=over 4
=item a M<Crypt::OpenSSL::RSA> object
containing the private key, for instance created via its
C<new_private_key()> method.

=item a filename
The private key is read from the FILENAME. Typically, the filename
ends on ".pem".

=item a string
The private key is provided as string, formatted the same way as a PEM
file looks.

=back

=subsection Public key

With C<public_key_type>, you specify the format of the public key.  By
default, the C<XTP10_X509> is taken.  You may also specify other C<XTP10_*>
constants M<XML::Compile::WSS::Util> tag-group C<:xtp10>.

For the C<public_key>, you have the same options as for the C<private_key>
option, although the object is created with new_public_key this time.
If the $pubkey is not provided, the $privkey object is used.

The C<publish_pubkey> can be a prefined constant or a CODE reference. This
function will be called then the C<wsse:Security> structure is being
constructed.  It puts the public key information in the right Perl
structure to be translated into XML automatically.  The only defined
constant is C<INCLUDE_BY_REF>.
=cut

sub _setup_hashing_rsa($$)
{   my ($self, $hashing, $args) = @_;

    require Crypt::OpenSSL::RSA;

    my $pkt = $self->{XCWS_pubkey_t} = $args->{public_key_type} || XTP10_X509;

    ### Private key
    my $priv = $args->{private_key}
        or error "signer rsa requires the private_rsa key";

    my $privkey = $self->{XCWS_privkey}
      = blessed $priv && $priv->isa('Crypt::OpenSSL::RSA') ? $priv
      : index($priv, "\n") >= 0
      ? Crypt::OpenSSL::RSA->new_private_key($priv)
      : Crypt::OpenSSL::RSA->new_private_key(scalar read_file $priv);

    ### Public key
    my $pub    = $args->{public_key} || $privkey;
    my $pubkey = $self->{XCWS_pubkey}
      = blessed $pub && $pub->isa('Crypt::OpenSSL::RSA')? $pub
      : index($pub, "\n") >= 0
      ? Crypt::OpenSSL::RSA->new_public_key($pub)
      : Crypt::OpenSSL::RSA->new_public_key(scalar read_file $pub);

    ### Hashing
    my $use_hash = "use_\L$hashing\E_hash";
    $privkey->can($use_hash)
        or error __x"hash {type} not supported by {pkg}"
            , type => $hashing, pkg => ref $privkey;
    $privkey->$use_hash();

    $self->{XCWS_hasher} = sub { my $rtext = shift; $privkey->sign($$rtext) };

    my $pub64
      = $pkt eq XTP10_X509    ? $pubkey->get_public_key_x509_string
      : $pkt eq XTP10_X509PKI ? $pubkey->get_public_key_string
      : error __x"rsa unsupported public key format {type}", type => $pkt;

    $pub64 =~ s/^---[^\n]*\n//gm;   # remove wrapper
    $self->{XCWS_pubkey_base64} = $pub64;
    $self;
}

sub _checker_from_token_rsa($$)
{   my ($self, $hashing, $token) = @_;

    require Crypt::OpenSSL::RSA;
#cache here based on token?  Performance worth the effort?

    my $key = $token->{_};
    my $enc = $token->{EncodingType};

    if(!$enc)
    {   $key = encode_base64 $key;
        $enc = WSM10_BASE64;
    }
    elsif($enc eq WSM10_BASE64) {}
    else {error __x"unsupported token encoding {type} received", type => $enc}

    my $vtype  = $token->{ValueType};
    my $wrap   = $keywraps{$vtype}
        or error __x"unsupported token type {type} received", type => $vtype;

    # the input format of openssl is very strict
    for($key)
    {   s/\s+//gs;
        s/(.{64})/$1\n/g;   # exactly 64 chars per line
        s/\s*\z//s;
    }
    my $pubkey = Crypt::OpenSSL::RSA->new_public_key(<<__PUBLIC_KEY);
-----BEGIN $wrap-----
$key
-----END $wrap-----
__PUBLIC_KEY

    my $use_hash = "use_\L$hashing\E_hash";
    $pubkey->can($use_hash)
        or error __x"hash {type} not supported by {pkg}"
            , type => $hashing, pkg => ref $pubkey;
    $pubkey->$use_hash();
    $self->_check_rsa($pubkey);
}

sub _check_rsa($)
{   my ($self, $pubkey) = @_;
    sub { my ($plain, $sig) = @_; $pubkey->verify($$plain, $sig) }
}

1;
