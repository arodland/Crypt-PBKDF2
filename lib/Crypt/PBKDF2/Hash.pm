package Crypt::PBKDF2::Hash;
# ABSTRACT: Abstract role for PBKDF2 hashing algorithms.
# VERSION
# AUTHORITY
use Moose::Role;
use namespace::autoclean;

requires 'hash_len';

requires 'generate';

requires 'to_algo_string';

requires 'from_algo_string';

1;

=pod

=method hash_len()

Returns the length (in bytes) of the hashes this algorithm generates.

=method generate($data, $key)

Generate strong pseudorandom bits based on the C<$data> and C<$key>

=method to_algo_string()

Return a string representing any optional arguments this object was created
with, for use by L<Crypt::PBKDF2>'s C<generate> and C<encode_string>
methods. May return undef if no arguments are required, in which case none
will be serialized and C<from_algo_string> won't be called on reading the
hash.

=method from_algo_string($str)

Given a string as produced by C<from_algo_string>, return an instance of
this class with options corresponding to those in C<$str>. If no options are
expected, it's permissible for this method to throw an exception.
