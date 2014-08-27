package Crypt::PBKDF2::Hash::HMACSHA3;
# ABSTRACT: HMAC-SHA3 support for Crypt::PBKDF2 using Digest::SHA
# VERSION
# AUTHORITY
use Moose 1;
use Moose::Util::TypeConstraints;
use namespace::autoclean;
use Digest::HMAC 1.01 ();
use Digest::SHA3 0.22 ();

with 'Crypt::PBKDF2::Hash';

subtype 'SHASize' => (
  as 'Int',
  where { $_ == 224 or $_ == 256 or $_ == 384 or $_ == 512 },
  message { "$_ is an invalid number of bits for SHA-3" }
);

has 'sha_size' => (
  is => 'ro',
  isa => 'SHASize',
  default => 256,
);

has '_hasher' => (
  is => 'ro',
  lazy_build => 1,
  init_arg => undef,
);

sub _build__hasher {
  my $self = shift;
  my $shasize = $self->sha_size;

  return Digest::SHA3->can("sha3_$shasize");
}

sub hash_len {
  my $self = shift;
  return $self->sha_size() / 8;
}

sub generate {
  my ($self, $data, $key) = @_;
  return Digest::HMAC::hmac($data, $key, $self->_hasher);
}

sub to_algo_string {
  my $self = shift;

  return $self->sha_size;
}

sub from_algo_string {
  my ($class, $str) = @_;

  return $class->new( sha_size => $str );
}

__PACKAGE__->meta->make_immutable;
1;

=head1 DESCRIPTION

Uses L<Digest::HMAC> and L<Digest::SHA3> C<sha3_256>/C<sha3_384>/C<sha3_512>
to provide the HMAC-ShA3 family of hashes for L<Crypt::PBKDF2>.

This could be done with L<Crypt::PBKDF2::Hash::DigestHMAC> instead, but it
seemed nice to have a uniform interface to HMACSHA*.
