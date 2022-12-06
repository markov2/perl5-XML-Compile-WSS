use warnings;
use strict;

package XML::Compile::WSS::BasicAuth;
use base 'XML::Compile::WSS';

use Log::Report  'xml-compile-wss';

use XML::Compile::WSS::Util qw/:wss11 :utp11/;

use Digest::SHA1 qw/sha1_base64/;
use Encode       qw/encode/;
use MIME::Base64 qw/encode_base64/;
use POSIX        qw/strftime/;

=chapter NAME
XML::Compile::WSS::BasicAuth - username/password security

=chapter SYNOPSIS

 # you may need a few of these
 use XML::Compile::WSS::Util  qw/:utp11/;

 # used in combination with anything
 my $auth = XML::Compile::WSS::BasicAuth->new
   ( schema   => $anything
   , username => $user
   , password => $password
   );

 # connects itself to a WSDL
 my $wss  = XML::Compile::SOAP::WSS->new;
 my $wsdl = XML::Compile::WSDL11->new($wsdlfn);
 my $auth = $wss->basicAuth
   ( ... same params, except 'schema'
   );

=chapter DESCRIPTION
The generic Web Service Security protocol is implemented by the super
class M<XML::Compile::WSS>.  This extension implements "basic authentication",
i.e. username/password validation.

You can best use digested passwords (UTP11_PDIGEST)  In that case,
a timestamp, a nonce and SHA1 hashing will keep the password a secret.

=chapter METHODS

=section Constructors

=c_method new OPTIONS

=default wss_version  '1.1'

=requires username STRING
=requires password STRING

=option   pwformat UTP11_PTEXT|UTP11_PDIGEST
=default  pwformat UTP11_PTEXT
With C<UTP11_PTEXT>, the plain-text version of the password is shown.
If PTWTYPE IS C<UTP11_PDIGEST>, the plain-text password will be
encrypted with SHA1.  The OPTIONS can be used to salt the digest
with "nonce" and/or "created" information before the encryption.

=option  created DATETIME
=default created undef
See M<XML::Compile::WSS::dateTime()> for choices of DATETIME.

=option  nonce STRING|CODE|'RANDOM'
=default nonce 'RANDOM'
Only used then the password is passed as digest.  This will cause the
C<wsse:Nonce> element.

When you pass a CODE, it will get called for each message to produce a
STRING. The constant text 'RANDOM' will have a random nonce generator
being called at each message.

=option  wsu_Id STRING
=default wsu_Id undef
Adds a C<wsu:Id> attribute to the created element.

=cut

my @nonce_chars = ('A'..'Z', 'a'..'z', '0'..'9');
sub _random_nonce() { join '', map $nonce_chars[rand @nonce_chars], 1..5 }

sub init($)
{   my ($self, $args) = @_;
    $args->{wss_version} ||= '1.1';
    $self->SUPER::init($args);

    $self->{XCWB_username} = $args->{username} or panic;
    $self->{XCWB_password} = $args->{password} or panic;

    my $n     = defined $args->{nonce} ? $args->{nonce} : 'RANDOM';
    my $nonce = ref $n eq 'CODE' ? $n
              : $n eq 'RANDOM'   ? \&_random_nonce
              :                    sub { $n };

    $self->{XCWB_nonce}    = $args->{nonce};
    $self->{XCWB_wsu_id}   = $args->{wsu_Id}   || $args->{wsu_id};
    $self->{XCWB_created}  = $args->{created};
    $self->{XCWB_pwformat} = $args->{pwformat} || UTP11_PTEXT;
    $self;
}

#----------------------------------
=section Attributes
=method username
=method password
=method nonce
=method wsuId
=method created
=cut

sub username() {shift->{XCWB_username}}
sub password() {shift->{XCWB_password}}
sub nonce()    {shift->{XCWB_nonce}   }
sub wsuId()    {shift->{XCWB_wsu_id}  }
sub created()  {shift->{XCWB_created} }
sub pwformat() {shift->{XCWB_pwformat}}

# To be merged with the one a level lower.
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

sub prepareWriting($)
{   my ($self, $schema) = @_;
    $self->SUPER::prepareWriting($schema);
    return if $self->{XCWB_login};

    my $nonce_type = $schema->findName('wsse:Nonce') ;
    my $w_nonce    = $schema->writer($nonce_type, include_namespaces => 0);
    my $make_nonce = sub {
        my ($doc, $nonce) = @_;
        my $enc = encode_base64 $nonce;
        $enc    =~ s/\n$//;
        $w_nonce->($doc, {_ => $enc});
    };

    my $created_type = $schema->findName('wsu:Created');
    my $w_created    = $schema->writer($created_type, include_namespaces => 0);
    my $make_created = sub {
        my ($doc, $created) = @_;
        $w_created->($doc, $created);
    };

    my $pw_type = $schema->findName('wsse:Password');
    my $w_pw    = $schema->writer($pw_type, include_namespaces => 0);
    my $make_pw = sub {
        my ($doc, $password, $pwformat) = @_;
        $w_pw->($doc, {_ => $password, Type => $pwformat});
    };

    # UsernameToken is allowed to have an "wsu:Id" attribute
    # We set up the writer with a hook to add that particular attribute.
    my $un_type = $schema->findName('wsse:UsernameToken');
    my $make_un = $schema->writer($un_type, include_namespaces => 1,
      , hook => { type    => 'wsse:UsernameTokenType'
                , replace => \&_hook_WSU_ID});
    $schema->prefixFor(WSU_10);  # to get ns-decl

    $self->{XCWB_login} = sub {
        my ($doc, $data) = @_;

        my %login =
          ( wsu_Id        => $self->wsuId
          , wsse_Username => $self->username
          );

        my $created  = $self->dateTime($self->created) || '';
        $login{$created_type} = $make_created->($doc, $created) if $created;

        my $nonce    = $self->nonce || '';
        $login{$nonce_type} = $make_nonce->($doc, $nonce)
            if length $nonce;

        my $pwformat = $self->pwformat;
        my $password = $self->password;
        $created  = $created->{_} if ref $created eq 'HASH';
        $password = sha1_base64(encode utf8 => "$nonce$created$password").'='
            if $pwformat eq UTP11_PDIGEST;

        $login{$pw_type}  = $make_pw->($doc, $password, $pwformat);
        $data->{$un_type} = $make_un->($doc, \%login);
        $data;
    };
}

sub create($$)
{   my ($self, $doc, $data) = @_;
    $self->{XCWB_login}->($doc, $data);
}

1;
