use warnings;
use strict;

package XML::Compile::WSS::Util;
use base 'Exporter';

use Log::Report    'xml-compile-wss';
use MIME::Base64   qw/decode_base64 encode_base64/;

my @wss11 = qw/
WSS_11		WSS11MODULE	WSM_10		WSM_11		WSU_10
WSSE_10
DSIG_NS		XENC_NS		DSIG11_NS	DSP_NS		DSIG_MORE_NS
GHC_NS		WSU_NS
 /;

my @dsig  = qw/
DSIG_BASE64	DSIG_HMAC_SHA1	DSIG_OBJECT	DSIG_SHA1	DSIG_X509_DATA
DSIG_DSA_KV	DSIG_MANIFEST	DSIG_PGP_DATA	DSIG_SIGPROPS	DSIG_XPATH
DSIG_DSA_SHA1	DSIG_MGMT_DATA	DSIG_RSA_KV	DSIG_SPKI_DATA	DSIG_XSLT
DSIG_ENV_SIG	DSIG_NS		DSIG_RSA_SHA1	DSIG_X509_CERT
 /;

my @dsig_more = qw/
DSIGM_MD5		DSIGM_ECDSA_SHA224	DSIGM_CAM192
DSIGM_SHA224		DSIGM_ECDSA_SHA256	DSIGM_CAM256
DSIGM_SHA384		DSIGM_ECDSA_SHA384	DSIGM_KW_CAM128
DSIGM_HMAC_MD5		DSIGM_ECDSA_SHA512	DSIGM_KW_CAM192
DSIGM_HMAC_SHA224	DSIGM_ESIGN_SHA1	DSIGM_KW_CAM256
DSIGM_HMAC_SHA256	DSIGM_ESIGN_SHA224	DSIGM_PSEC_KEM
DSIGM_HMAC_SHA384	DSIGM_ESIGN_SHA256	DSIGM_KV
DSIGM_HMAC_SHA512	DSIGM_ESIGN_SHA384	DSIGM_RETR_METHOD
DSIGM_HMAC_RIPEMD160	DSIGM_ESIGN_SHA512	DSIGM_KEY_NAME
DSIGM_RSA_MD5		DSIGM_DSA_SHA256	DSIGM_RAW_X509
DSIGM_RSA_SHA256	DSIGM_CURVE_URN		DSIGM_RAW_PGP
DSIGM_RSA_SHA384	DSIGM_XPTR		DSIGM_RAW_SPKIS
DSIGM_RSA_SHA512	DSIGM_ARCFOUR		DSIGM_PKCS7_DATA
DSIGM_ECDSA_SHA1	DSIGM_CAM128		DSIGM_RAW_PKCS7_DATA
 /;

my @dsig11 = qw/
DSIG11_NS		DSIG11_EC_KV		DSIG11_DER_KV
 /;

my @xtp10 = qw/XTP10_X509 XTP10_X509v3 XTP10_X509PKI XTP10_X509PKC/;

my @wsm10 = qw/
WSM10_BASE64	WSM10_STR_TRANS
wsm_encoded	wsm_decoded
 /;

my @wsm11 = qw/WSM11_PRINT_SHA1	WSM11_ENCKEY_SHA1 WSM11_ENCKEY/;

my @xenc  = qw/
XENC_NS		XENC_PROPS	XENC_AES128	XENC_DH		XENC_KW_AES256
XENC_MIME_TYPE	XENC_SHA256	XENC_AES192	XENC_DH_KV	XENC_DSIG
XENC_ELEMENT	XENC_SHA512	XENC_AES256	XENC_KW_3DES
XENC_CONTENT	XENC_RIPEMD160	XENC_RSA_1_5	XENC_KW_AES128
XENC_KEY	XENC_3DES	XENC_RSA_OAEP	XENC_KW_AES192
 /;

my @ghc = qw/
GHC_NS		GHC_GENERIC	GHC_RSAES_KEM	GHC_ECIES_KEM
 /;

my @dsp = qw/
DSP_NS
 /;

my @utp11 = qw/
UTP11_PTEXT     UTP11_PDIGEST   UTP11_USERNAME
 /;

our @EXPORT    = 'WSS11MODULE';
our @EXPORT_OK
  = ( @wss11, @dsig, @dsig_more, @dsig11, @xenc, @ghc, @dsp, @utp11
    , @wsm10, @wsm11, @xtp10);

our %EXPORT_TAGS =
  ( wss11  => \@wss11
  , dsig   => \@dsig
  , dsig11 => \@dsig11
  , dsigm  => \@dsig_more
  , xenc   => \@xenc
  , ghc    => \@ghc
  , dsp    => \@dsp
  , utp11  => \@utp11
  , xtp10  => \@xtp10
  , wsm10  => \@wsm10
  , wsm11  => \@wsm11
  );

=chapter NAME
XML::Compile::WSS::Util - constants for XML::Compile::WSS

=chapter SYNOPSIS

 use XML::Compile::WSS::Util qw/:wss11/;

=chapter DESCRIPTION
This module collects constants used by various standards related
to the Web Service Security (WSS) group of W3C.

These constants may also be used by other applications: they are
not limited to the M<XML::Compile::WSS> module. Please inform me
when you use this list in combination with other applications.

=chapter CONSTANTS
=cut

# Path components, not exported
use constant
  { WSS_BASE => 'http://docs.oasis-open.org/wss'
  , DSIG     => 'http://www.w3.org/2000/09/xmldsig'
  , DSIG11   => 'http://www.w3.org/2009/xmldsig11'
  , DSIGM    => 'http://www.w3.org/2001/04/xmldsig-more'
  , XENC     => 'http://www.w3.org/2001/04/xmlenc'
  , GHC      => 'http://www.w3.org/2010/xmlsec-ghc'
  , DSP      => 'http://www.w3.org/2009/xmldsig-properties'
  };

=section Export TAG :wss11

  WSS_11   WSSE_10      DSIG_NS      DSIG11_NS    GHC_NS
  WSU_10   WSS11MODULE  DSIG_MORE_NS XENC_NS      DSP_NS
  WSM_10   XTP_10	WSU_NS

=cut

use constant WSS_WG200401 => WSS_BASE.'/2004/01/oasis-200401-wss';
use constant
  { WSU_10  => WSS_WG200401.'-wssecurity-utility-1.0.xsd' 
  , WSSE_10 => WSS_WG200401.'-wssecurity-secext-1.0.xsd'
  , UTP_10  => WSS_WG200401.'-username-token-profile-1.0'
  , XTP_10  => WSS_WG200401.'-x509-token-profile-1.0'
  , WSM_10  => WSS_WG200401.'-soap-message-security-1.0'

  , WSS_11  => WSS_BASE.'/oasis-wss-wssecurity-secext-1.1.xsd'
  , WSM_11  => WSS_BASE.'/oasis-wss-soap-message-security-1.1'
  };

use constant
  { WSS11MODULE => WSS_11
  , WSU_NS      => WSU_10
  };

=section Export tag :xtp10
Defines convenient constants in the x509 namespace. See
F<http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-x509-token-profile-1.0.pdf>

  XTP10_X509   XTP10_X509v3   XTP10_X509PKI   XTP10_X509PKC

=cut

use constant
  { XTP10_X509    => XTP_10.'#X509'
  , XTP10_X509v3  => XTP_10.'#X509v3'
  , XTP10_X509PKI => XTP_10.'#X509PKIPathv1'
  , XTP10_X509PKC => XTP_10.'#X509PKCS7'
  };

=section Export tag :wsm10
Defines convenient constants in the soap-messages namespace.  See
F<http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0.pdf >

  WSM10_BASE64    WSM10_STR_TRANS

=cut

use constant
  { WSM10_BASE64      => WSM_10.'#Base64Binary'
  , WSM10_STR_TRANS   => WSM_10.'#STRTransform'
  };

=function wsm_encoded $encoding, $bytes
Encode the sequence of $bytes into the preferred.
=cut

sub wsm_encoded($$)
{   my ($enc, $bytes) = @_;

    return encode_base64 $bytes
        if $enc eq WSM10_BASE64;

    panic "unsupported encoding style $enc for encoding";
}

=function wsm_decoded $encoding, $bytes
Decode the sequence of $bytes from the given encoding.
=cut

sub wsm_decoded($$)
{   my ($dec, $bytes) = @_;
    $dec or return $bytes;

    return decode_base64 $bytes
        if $dec eq WSM10_BASE64;

    panic "unsupported encoding style $dec for decoding";
}

=section Export tag :wsm11
[1.08] Defines convenient constants in the soap-messages namespace.  See
F<http://docs.oasis-open.org/wss-m/wss/v1.1.1/os/wss-SOAPMessageSecurity-v1.1.1-os.html>

=cut

use constant
  { WSM11_PRINT_SHA1  => WSM_11.'#ThumbprintSHA1'
  , WSM11_ENCKEY_SHA1 => WSM_11.'#EncryptedKeySHA1'
  , WSM11_ENCKEY      => WSM_11.'#EncryptedKey'
  };

=section Export tag C<:utp11>
Defines constants for the username-token-profile.
See F<http://docs.oasis-open.org/wss/v1.1/wss-v1.1-spec-os-UsernameTokenProfile.pdf>

  UTP11_PTEXT   UTP11_PDIGEST   UTP11_USERNAME

=cut

use constant   # Yes, I know... it is correct, v1.1 uses the 1.0 namespace
  { UTP11_PTEXT    => UTP_10.'#PasswordText'
  , UTP11_PDIGEST  => UTP_10.'#PasswordDigest'
  , UTP11_USERNAME => UTP_10.'#UsernameToken'
  };

=section Export tag :dsig
Defines convenient constants for signature reference URIs, mainly specified in
F<http://www.w3.org/TR/2008/REC-xmldsig-core-20080610/>

  DSIG_NS           DSIG_MGMT_DATA      DSIG_XML11_NO_COMM
  DSIG_SIGPROPS     DSIG_X509_CERT      DSIG_XML11_COMMENTS
  DSIG_OBJECT       DSIG_SHA1           DSIG_XMLEXC_NO_COMM
  DSIG_MANIFEST     DSIG_BASE64         DSIG_XMLEXC_COMMENTS
  DSIG_DSA_KV       DSIG_HMAC_SHA1      DSIG_XSLT
  DSIG_RSA_KV       DSIG_DSA_SHA1       DSIG_XPATH
  DSIG_X509_DATA    DSIG_RSA_SHA1       DSIG_ENV_SIG
  DSIG_PGP_DATA     DSIG_XML10_NO_COMM
  DSIG_SPKI_DATA    DSIG_XML10_COMMENTS

=cut

use constant
  { DSIG_NS        => DSIG.'#'

  , DSIG_SIGPROPS  => DSIG.'#SignatureProperties'
  , DSIG_OBJECT    => DSIG.'#Object'
  , DSIG_MANIFEST  => DSIG.'#Manifest'

  , DSIG_DSA_KV    => DSIG.'#DSAKeyValue'
  , DSIG_RSA_KV    => DSIG.'#RSAKeyValue'
  , DSIG_X509_DATA => DSIG.'#X509Data'
  , DSIG_PGP_DATA  => DSIG.'#PGPData'
  , DSIG_SPKI_DATA => DSIG.'#SPKIData'
  , DSIG_MGMT_DATA => DSIG.'#MgmtData'

    # Message Digest
  , DSIG_SHA1      => DSIG.'#sha1'
 
    # Encodings
  , DSIG_BASE64    => DSIG.'#base64'
 
    # MACs
  , DSIG_HMAC_SHA1 => DSIG.'#hmac-sha1'
 
    # Signatures
  , DSIG_DSA_SHA1  => DSIG.'#dsa-sha1'  # dss
  , DSIG_RSA_SHA1  => DSIG.'#rsa-sha1'
 
    # Transform
  , DSIG_XSLT      => 'http://www.w3.org/TR/1999/REC-xslt-19991116'
  , DSIG_XPATH     => 'http://www.w3.org/TR/1999/REC-xpath-19991116'
  , DSIG_ENV_SIG   => DSIG.'#enveloped-signature'
  };

=section Export tag :dsigm (dsigm-more)
Defines constants defined by RFC4050 and RFC4051.

=over 4
=item * RFC4050 Using the ECDSA for XML Digital Signatures F<http://www.ietf.org/rfc/rfc4050.txt>
=item * RFC4051 Additional XML Security Uniform Resource Identifiers (URIs) F<http://www.ietf.org/rfc/rfc4051.txt>
=back

  DSIGM_MD5             DSIGM_ECDSA_SHA224    DSIGM_CAM192
  DSIGM_SHA224          DSIGM_ECDSA_SHA256    DSIGM_CAM256
  DSIGM_SHA384          DSIGM_ECDSA_SHA384    DSIGM_KW_CAM128
  DSIGM_HMAC_MD5        DSIGM_ECDSA_SHA512    DSIGM_KW_CAM192
  DSIGM_HMAC_SHA224     DSIGM_ESIGN_SHA1      DSIGM_KW_CAM256
  DSIGM_HMAC_SHA256     DSIGM_ESIGN_SHA224    DSIGM_PSEC_KEM
  DSIGM_HMAC_SHA384     DSIGM_ESIGN_SHA256    DSIGM_KV
  DSIGM_HMAC_SHA512     DSIGM_ESIGN_SHA384    DSIGM_RETR_METHOD
  DSIGM_HMAC_RIPEMD160  DSIGM_ESIGN_SHA512    DSIGM_KEY_NAME
  DSIGM_RSA_MD5         DSIGM_DSA_SHA256      DSIGM_RAW_X509
  DSIGM_RSA_SHA256      DSIGM_CURVE_URN       DSIGM_RAW_PGP
  DSIGM_RSA_SHA384      DSIGM_XPTR            DSIGM_RAW_SPKIS
  DSIGM_RSA_SHA512      DSIGM_ARCFOUR         DSIGM_PKCS7_DATA
  DSIGM_ECDSA_SHA1      DSIGM_CAM128          DSIGM_RAW_PKCS7_DATA

=cut

# Some weird gaps, for instance: why are sha256 and sha512 missing?
use constant
  { DSIG_MORE_NS => DSIGM.'#'

    # Message Digest
  , DSIGM_MD5          => DSIGM.'#md5'
  , DSIGM_SHA224       => DSIGM.'#sha224'
  , DSIGM_SHA384       => DSIGM.'#sha384'
 
    # MACs
  , DSIGM_HMAC_MD5     => DSIGM.'#hmac-md5'
  , DSIGM_HMAC_SHA224  => DSIGM.'#hmac-sha224'
  , DSIGM_HMAC_SHA256  => DSIGM.'#hmac-sha256'
  , DSIGM_HMAC_SHA384  => DSIGM.'#hmac-sha384'
  , DSIGM_HMAC_SHA512  => DSIGM.'#hmac-sha512'
  , DSIGM_HMAC_RIPEMD160  => DSIGM.'#hmac-ripemd160'

    # Signatures
  , DSIGM_RSA_MD5      => DSIGM.'#rsa-md5'
  , DSIGM_RSA_SHA256   => DSIGM.'#rsa-sha256'
  , DSIGM_RSA_SHA384   => DSIGM.'#rsa-sha384'
  , DSIGM_RSA_SHA512   => DSIGM.'#rsa-sha512'
  , DSIGM_ECDSA_SHA1   => DSIGM.'#ecdsa-sha1'
  , DSIGM_ECDSA_SHA224 => DSIGM.'#ecdsa-sha224'
  , DSIGM_ECDSA_SHA256 => DSIGM.'#ecdsa-sha256'
  , DSIGM_ECDSA_SHA384 => DSIGM.'#ecdsa-sha384'
  , DSIGM_ECDSA_SHA512 => DSIGM.'#ecdsa-sha512'
  , DSIGM_ESIGN_SHA1   => DSIGM.'#esign-sha1'
  , DSIGM_ESIGN_SHA224 => DSIGM.'#esign-sha224'
  , DSIGM_ESIGN_SHA256 => DSIGM.'#esign-sha256'
  , DSIGM_ESIGN_SHA384 => DSIGM.'#esign-sha384'
  , DSIGM_ESIGN_SHA512 => DSIGM.'#esign-sha512'
  , DSIGM_DSA_SHA256   => DSIGM.'#dsa-sha256'

  , DSIGM_CURVE_URN    => 'urn:oid:1.2.840.10045.3.1.1'
  , DSIGM_XPTR         => DSIGM.'/xptr'

    # Encryption algorithms
  , DSIGM_ARCFOUR      => DSIGM.'#arcfour'
  , DSIGM_CAM128       => DSIGM.'#camellia128-cbc'
  , DSIGM_CAM192       => DSIGM.'#camellia192-cbc'
  , DSIGM_CAM256       => DSIGM.'#camellia256-cbc'
  , DSIGM_KW_CAM128    => DSIGM.'#kw-camellia128'
  , DSIGM_KW_CAM192    => DSIGM.'#kw-camellia192'
  , DSIGM_KW_CAM256    => DSIGM.'#kw-camellia256'
  , DSIGM_PSEC_KEM     => DSIGM.'#psec-kem'

    # Retreival method types
  , DSIGM_KV           => DSIGM.'#KeyValue'
  , DSIGM_RETR_METHOD  => DSIGM.'#RetrievalMethod'
  , DSIGM_KEY_NAME     => DSIGM.'#KeyName'
  , DSIGM_RAW_X509     => DSIGM.'#rawX509CRL'
  , DSIGM_RAW_PGP      => DSIGM.'#rawPGPKeyPacket'
  , DSIGM_RAW_SPKIS    => DSIGM.'#rawSPKISexp'
  , DSIGM_PKCS7_DATA   => DSIGM.'#PKCS7signedData'
  , DSIGM_RAW_PKCS7_DATA => DSIGM.'#rawPKCS7signedData'
 };

=section Export tag :dsig11
Defines convenient constants for the extensions on dsig, defined in
F<http://www.w3.org/TR/2011/CR-xmldsig-core1-20110303/>

  DSIG11_NS       DSIG11_EC_KV    DSIG11_DER_KV   DSIG_X509_CERT

=cut

use constant
 { DSIG11_NS      => DSIG11.'#'
 , DSIG11_EC_KV   => DSIG11.'#ECKeyValue'
 , DSIG11_DER_KV  => DSIG11.'#DEREncodedKeyValue'

 , DSIG_X509_CERT => DSIG.'#rawX509Certificate'
 };

=section Export tag :xenc
Defines convenient constants for encryption referencing URIs, mainly
specified in F<http://www.w3.org/TR/2002/REC-xmlenc-core-20021210/>

  XENC_NS         XENC_PROPS      XENC_AES128     XENC_DH
  XENC_MIME_TYPE  XENC_SHA256     XENC_AES192     XENC_DH_KV
  XENC_ELEMENT    XENC_SHA512     XENC_AES256     XENC_KW_3DES
  XENC_CONTENT    XENC_RIPEMD160  XENC_RSA_1_5    XENC_KW_AES128
  XENC_KEY        XENC_3DES       XENC_RSA_OAEP   XENC_KW_AES192
  XENC_DSIG       XENC_KW_AES256

=cut

use constant
  { XENC_NS        => XENC.'#'
  , XENC_MIME_TYPE => 'application/xenc+xml'

  , XENC_ELEMENT   => XENC.'#Element'
  , XENC_CONTENT   => XENC.'#Content'
  , XENC_KEY       => XENC.'#EncryptedKey'
  , XENC_PROPS     => XENC.'#EncryptionProperties'

    # Message Digest
  , XENC_SHA256    => XENC.'#sha256'
  , XENC_SHA512    => XENC.'#sha512'
  , XENC_RIPEMD160 => XENC.'#ripemd160'

    # Block Encryption
  , XENC_3DES      => XENC.'#tripledes-cbc'
  , XENC_AES128    => XENC.'#aes128-cbc'
  , XENC_AES192    => XENC.'#aes192-cbc'
  , XENC_AES256    => XENC.'#aes256-cbc'
 
    # Key Transport
  , XENC_RSA_1_5   => XENC.'#rsa-1_5'
  , XENC_RSA_OAEP  => XENC.'#rsa-oaep-mgf1p'
 
    # Key Agreement
  , XENC_DH        => XENC.'#dh'
  , XENC_DH_KV     => XENC.'#DHKeyValue'
 
    # Symmetric Key Wrap
  , XENC_KW_3DES   => XENC.'#kw-tripledes'
  , XENC_KW_AES128 => XENC.'#kw-aes128'
  , XENC_KW_AES192 => XENC.'#kw-aes192'
  , XENC_KW_AES256 => XENC.'#kw-aes256'
 
    # Message Authentication
  , XENC_DSIG      => DSIG_NS
  };

=section Export tag :xghc
Defines convenient constants for generic hybrid
algorithm referencing URIs, as specified in
F<http://www.w3.org/TR/2011/CR-xmlsec-generic-hybrid-20110303/>

  GHC_NS      GHC_GENERIC     GHC_RSAES_KEM     GHC_ECIES_KEM

=cut

use constant
  { GHC_NS         => GHC.'#'

    # Generic Hybrid Encryption
  , GHC_GENERIC    => GHC.'#generic-hybrid'

    # Key Encapsulation
  , GHC_RSAES_KEM  => GHC.'#rsaes-kem'
  , GHC_ECIES_KEM  => GHC.'#ecies-kem'
  };

=section Export tag :dsp
Defines constants for "Digital signature properties" as specified in
F<http://www.w3.org/TR/2011/CR-xmldsig-properties-20110303/>

  DSP_NS

=cut

use constant
  { DSP_NS => DSP
  };

1;
