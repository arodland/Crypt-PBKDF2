package Crypt::PBKDF2::Hash::HMACSHA1;
# ABSTRACT: HMAC-SHA1 support for Crypt::PBKDF2 using Digest::SHA

use Moose;
use namespace::autoclean;
use Digest::SHA ();
use Carp qw(croak);

with 'Crypt::PBKDF2::Hash';

sub hash_len {
  return 20;
}

sub generate {
  my $self = shift; # ($data, $key)
  return Digest::SHA::hmac_sha1(@_);
}

sub to_algo_string {
  return;
}

sub from_algo_string {
  croak "No argument expected";
}

__PACKAGE__->meta->make_immutable;
1;

=head1 DESCRIPTION

Uses L<Digest::SHA> C<hmac_sha1> to provide the HMAC-SHA1 backend for
L<Crypt::PBKDF2>.
