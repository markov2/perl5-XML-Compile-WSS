use warnings;
use strict;

package XML::Compile::WSS::Timestamp;
use base 'XML::Compile::WSS';

use Log::Report  'xml-compile-wss';

use XML::Compile::WSS::Util qw/WSU_10/;

=chapter NAME
XML::Compile::WSS::Timestamp - expiration

=chapter SYNOPSIS

 # used in combination with any XML schema
 my $wss = XML::Compile::WSS::Timestamp->new
   ( ... parametes, some required
   , schema => $anything
   );

 # connects itself to a WSDL
 my $wss  = XML::Compile::SOAP::WSS->new;
 my $wsdl = XML::Compile::WSDL11->new($wsdlfn);
 my $ts   = $wss->timestamp
   ( ... same params, never 'schema'
   );

=chapter DESCRIPTION
The generic Web Service Security protocol is implemented by the super
class M<XML::Compile::WSS>.  This extension implements a timestamp
record.

=chapter METHODS

=section Constructors

=c_method new OPTIONS

=default wss_version  '1.1'

=option  created  DATETIME
=default created  C<now>
By default, for each constructed message the current time is taken.
See M<XML::Compile::WSS::dateTime()> for options on DATETIME.  If you
specify an empty string, then the C<Created> node will be skipped.

=option  expires  DATETIME
=default expires  C<undef>
See M<XML::Compile::WSS::dateTime()> for options on DATETIME.  When
not defined, the C<Expires> node will be skipped.

=option  lifetime SECONDS
=default lifetime C<undef>
When C<lifetime> is given and no C<expires>, then the expiration will
be set to the C<created> time plus this lifetime.  In this case, the
created time cannot be specified as formatted DATE.

=option  wsu_Id LABEL
=default wsu_Id undef
Adds a C<wsu:Id> attribute to the C<wsse:Timestamp>.

=cut

sub init($)
{   my ($self, $args) = @_;
    $args->{wss_version} ||= '1.1';
    $self->SUPER::init($args);

    $self->{XCWT_created}  = $args->{created};
    $self->{XCWT_expires}  = $args->{expires};
    $self->{XCWT_lifetime} = $args->{lifetime};
    $self->{XCWT_wsu_id}   = $args->{wsu_Id} || $args->{wsu_id};
    $self;
}

#----------------------------------
=section Attributes

=method created
=method expires
=method lifetime
=method wsuId
=cut

sub created()  {shift->{XCWT_created}}
sub expires()  {shift->{XCWT_expires}}
sub lifetime() {shift->{XCWT_lifetime}}
sub wsuId()    {shift->{XCWT_wsu_id}}

=method timestamps
Returns the "created" and "expires" timestamps.  Both may be undef.
=cut

sub timestamps()
{   my $self    = shift;
    my ($c, $e, $l) = @{$self}{ qw/XCWT_created XCWT_expires XCWT_lifetime/ };
    my ($expires);

    defined $c or $c = time;
    my $created = $c eq '' ? undef : $self->dateTime($c);

    if(!$e && defined $l)
    {    $c !~ m/\D/ or error "lifetime only when created is in seconds";
         $e = $c + $l;
    }
    ($created, $self->dateTime($e));
}

sub prepareWriting($)
{   my ($self, $schema) = @_;
    $self->SUPER::prepareWriting($schema);
    return if $self->{XCWT_stamp};

    my $ts_type = $schema->findName('wsu:Timestamp') ;
    my $make_ts = $schema->writer($ts_type, include_namespaces => 1,
      , hook => $self->writerHookWsuId('wsu:TimestampType'));
    $schema->prefixFor(WSU_10);

    $self->{XCWT_stamp} = sub {
        my ($doc, $data) = @_;
        my ($created, $expires) = $self->timestamps;
        $data->{$ts_type} = $make_ts->($doc,
          { wsu_Id      => $self->wsuId
          , wsu_Created => $created
          , wsu_Expires => $expires
          });
        $data;
    };
}

sub create($$)
{   my ($self, $doc, $data) = @_;
    $self->SUPER::create($doc, $data);
    $self->{XCWT_stamp}->($doc, $data);
}

1;
