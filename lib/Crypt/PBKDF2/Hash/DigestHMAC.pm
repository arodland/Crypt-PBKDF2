package Crypt::PBKDF2::Hash::DigestHMAC;

use Moose;
use namespace::autoclean;
use Digest ();
use Digest::HMAC ();
use Try::Tiny;
use Carp qw(croak);

with 'Crypt::PBKDF2::Hash';

has digest_class => (
  is => 'ro',
  required => 1,
);

has _digest => (
  is => 'ro',
  lazy_build => 1,
  init_arg => undef,
);

sub _build__digest {
  my $self = shift;

  return Digest->new($self->digest_class);
}

sub BUILD {
  my $self = shift;

  try {
    my $digest = $self->_digest;
  } catch {
    croak "Couldn't construct a Digest of type " . $self->digest_class . ": $_";
  }
}

sub hash_len {
  my $self = shift;
  return length( $self->_digest->clone->add("")->digest );
}

sub generate {
  my ($self, $data, $key) = @_;
  
  my $digest = $self->_digest->clone;

  return Digest::HMAC::hmac($data, $key,
    sub { $digest->add(@_)->digest });
}

sub to_algo_string {
  my $self = shift;

  return $self->digest_class;
}

sub from_algo_string {
  my ($class, $str) = shift;

  return $class->new(digest_class => $str);
}

__PACKAGE__->meta->make_immutable;
1;
