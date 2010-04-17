package Crypt::PBKDF2::Hash::HMACSHA1;

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
