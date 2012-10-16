use warnings;
use strict;

package XML::Compile::WSS::Signature;
use base 'XML::Compile::WSS';

use Log::Report 'xml-compile-wss';

use XML::Compile::WSS::Util   qw/:wss11 :dsig :xtp10 :wsm10/;
use XML::Compile::C14N::Util  qw/:c14n/;

use XML::LibXML               ();
use HTTP::Response            ();
use MIME::Base64              qw/decode_base64 encode_base64/;
use File::Slurp               qw/read_file/;
use Digest                    ();

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

my ($digest_algorithm, $sign_algorithm);
{  my ($signs, $sigmns) = (DSIG_NS, DSIG_MORE_NS);
   # the digest algorithms can be distiguish by pure lowercase, no dash.
   $digest_algorithm = qr/^(?:$signs|$sigmns)([a-z0-9]+)$/;
   $sign_algorithm   = qr/^(?:$signs|$sigmns)([a-z0-9]+)\-([a-z0-9]+)$/;
}

=chapter NAME
XML::Compile::WSS::Signature - WSS in CICS-TS style

=chapter SYNOPSIS

 my $wss  = XML::Compile::WSS::Signature->new
    ( ... some required params, see below
    );

B<WARNING: under development!>

=chapter DESCRIPTION
The generic Web Service Security protocol is implemented by the super
class M<XML::Compile::WSS>.  This extension implements Signatures.

Limitations:
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

=option  sign_method SIGN
=default sign_method DSIG_RSA_SHA1

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

=option  public_key_uri STRING
=default public_key_uri '#public-key'

=option  publish_pubkey 'INCLUDE_BY_REF'|CODE
=default publish_pubkey 'INCLUDE_BY_REF'
How to publish the public key.  The C<INCLUDE_BY_REF> constant (currently
the only one supported) will add the key as BinarySecurityToken in the message,
plus a keyinfo structure with a reference to that token.
=cut

sub init($)
{   my ($self, $args) = @_;
    $args->{wss_version} ||= '1.1';

    $self->SUPER::init($args);

    # Run digest to initialize modules (and detect what is not installed)
    # Usually client and server use the same algorithms
    my $digest = $self->{XCWS_digmeth}  = $args->{digest_method} || DSIG_SHA1;
    $self->digest($digest, \"test digest");

    my $sign   = $self->{XCWS_signmeth} = $args->{sign_method} || DSIG_RSA_SHA1;
    $self->{XCWS_signer}     = $self->_create_signer($sign, $args);

    $self->{XCWS_pubkey_uri} = $args->{public_key_uri} || '#public-key';
    $self->{XCWS_publ_key}   = $args->{publish_pubkey} || 'INCLUDE_BY_REF';

    $self->{XCWS_canonmeth}  = $args->{canon_method}   || C14N_EXC_NO_COMM;
    $self->{XCWS_prefixlist} = $args->{prefix_list}
                            || [ qw/ds wsu xenc SOAP-ENV/ ];
    $self;
}

#-----------------------------

=section Digests

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

    my $digest = try { Digest->new($algo)->add($text)->digest };
    $@ and error __x"cannot use digest method {short}, constant {name}: {err}"
      , short => $algo, name => $method, err => $@->wasFatal;

    $digest;
}

sub checkDigest($%)
{   my ($self, $node, %args) = @_;
    my $id = $node->getAttributeNS(WSU_10, 'Id') or panic $node;

#   my $sig  = $signatures{$uri} or panic $uri;
#   my $ref  = $references{$uri} or panic $uri;
#   $self->_digest_elem_check($node, $ref)
# probably fails due to serialization problem of the body
#        or warning __x"received body digest does not match";
#    $node;
}

#-----------------------------

=section Canonicalization

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
        # XML::Compile has to trick with prefixes, because XML::LibXML does not
        # permit the creation of nodes with explicit prefix, only by namespace.
        # The next can be slow and is ugly, Sorry.  MO
        my $reparse = XML::LibXML->load_xml(string => $node->toString(0));
#       my $context = XML::LibXML::XPathContext->new($reparse->documentElement);
#       $reparse->$serialize($with_comments, $path, $context, $prefixlist)
        $reparse->$serialize($with_comments, undef, $prefixlist);
    };
}

sub _apply_canon_siginfo($$)
{   my ($self, $siginfo_node, $sig) = @_;

    my $canon = $sig->{ds_SignedInfo}{ds_CanonicalizationMethod} or panic;
    $self->_apply_canon
      ( $canon->{Algorithm}
      , $canon->{c14n_InclusiveNamespaces}{PrefixList}
      )->($siginfo_node);
}

#-----------------------------

=section KeyInfo
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
    my $krw = $schema->writer($krt);

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


=section Signing

=method signMethod
=cut

sub signMethod() {shift->{XCWS_signmeth}}

sub _create_signer($$)
{   my ($self, $method, $args) = @_;
    $method =~ $sign_algorithm
        or error __x"Method {name} is not a sign algorithm";
    my ($algo, $hashing) = (uc $1, uc $2);

    if($algo eq 'RSA') { $self->_setup_hashing_rsa($hashing, $args) }
    else
    {   error __x"signing algorithm {name} not (yet) unsupported", name => $hashing;
    }

}

=method signElement NODE, OPTIONS

=option  id LABEL
=default id C<unique>
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
    $wsuid;
}

=method elementsToSign
=cut

sub elementsToSign() { delete shift->{XCWS_to_sign} || [] }

#-----------------------------
#### HELPERS


sub _digest_elem_check($$)
{   my ($self, $elem, $ref) = @_;
    my $transf   = $ref->{ds_Transforms}{ds_Transform}[0]; # only 1 transform
    my ($inclns, $preflist) = %{$transf->{cho_any}[0]};    # only 1 kv pair
    my $elem_c14n = $self->_apply_canon($transf->{Algorithm}, $preflist)
        ->($elem);

#MO: Output not OK
print "TEXT=$elem_c14n";

    my $digmeth = $ref->{ds_DigestMethod}{Algorithm} || '(none)';
    $self->digest($digmeth, \$elem_c14n) eq $ref->{ds_DigestValue};
}

sub prepareReading($)
{   my ($self, $schema) = @_;
    $self->SUPER::prepareReading($schema);

    my %security_tokens;   # the BinarySecurityToken keys, binary form
    my %references;        # content of signature refs, by URI
    my %signatures;        # signature data, expanded per reference URI
    my @hooks;

    my $scan_security_info
      = { type    => 'wsse:SecurityHeaderType'
        , after   => sub {
        my ($node, $data, $path) = @_;
use Data::Dumper;
#print "HOOK: ", Dumper $data;
        if(my $sig = $data->{ds_Signature})
        {   # This will need to be extended, when we start to understand
            # more security protocols
            foreach my $ref (@{$sig->{ds_SignedInfo}{ds_Reference}})
            {   my $uri = $ref->{URI};
                $references{$uri} = $ref;
                $signatures{$uri} = $sig;
            }
        }

#print "FOUND = ", Dumper \%references, \%signatures;
        $data;
       }};

    my $take_security_token
      = { type    => 'wsse:BinarySecurityTokenType'
        , after   => sub {
        my ($node, $data, $path) = @_;
        my $id     = $data->{wsu_id} = $node->getAttributeNS(WSU_10, 'Id');

        if(my $enc = $data->{EncodingType})
        {   $enc eq WSM10_BASE64
                or error __x"security token encoding {type} not supported"
                    , type => $enc;
            $security_tokens{$id} = decode_base64 $data->{_};
        }

        $data;
       }};

    $schema->declare(READER => 'wsse:Security'
      , hooks => $scan_security_info);

    $schema->declare(READER => 'wsse:BinarySecurityToken'
      , hooks => $take_security_token);

    $self;
}

### BE WARNED: created nodes can only be used once!!! in XML::LibXML

sub _create_inclns($)
{   my ($self, $prefixes) = @_;
    $prefixes && @$prefixes or return ();

    my $schema = $self->schema;
    my $type   = $schema->findName('c14n:InclusiveNamespaces');
    my $incns  = $schema->writer($type);

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
        {   my $digested  = $self->digest($digest, $canonical->($part->{node}));
    
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
        my $info      = $fill_signed_info->($doc, $self->elementsToSign);
        my $keyinfo   = $settings->($doc, $sec);
        my $info_node = $infow->($doc, $info);
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

sub process($$)
{   my ($self, $doc, $data) = @_;
    $self->{XCWS_sign}->($doc, $data);
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
     , public_key_uri  => '#public-key'    # default
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
      = UNIVERSAL::isa($priv, 'Crypt::OpenSSL::RSA') ? $priv
      : index($priv, "\n") >= 0
      ? Crypt::OpenSSL::RSA->new_private_key($priv)
      : Crypt::OpenSSL::RSA->new_private_key(scalar read_file $priv);

    ### Public key
    my $pub    = $args->{public_key} || $privkey;
    my $pubkey = $self->{XCWS_pubkey}
      = UNIVERSAL::isa($pub, 'Crypt::OpenSSL::RSA') ? $pub
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
1;
