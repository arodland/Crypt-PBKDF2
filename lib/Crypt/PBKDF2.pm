package Crypt::PBKDF2; 
# ABSTRACT: The PBKDF2 password hashing algorithm.
use Moose 1;
use Method::Signatures::Simple;
use Moose::Util::TypeConstraints;
use namespace::autoclean;
use MIME::Base64 ();
use Carp qw(croak);
use Try::Tiny;

with 'MooseX::Clone';

=attr hash_class

B<Type:> String, B<Default:> HMACSHA1

The name of the default class that will provide PBKDF2's Pseudo-Random
Function (the backend hash). If the value starts with a C<+>, the C<+> will
be removed and the remainder will be taken as a fully-qualified package
name. Otherwise, the value will be appended to C<Crypt::PBKDF2::Hash::>.

=cut

has hash_class => (
  is => 'ro',
  isa => 'Str',
  default => 'HMACSHA1',
);

=attr hash_args

B<Type:> HashRef, B<Default:> {}

Arguments to be passed to the C<hash_class> constructor.

=cut

has hash_args => (
  is => 'ro',
  isa => 'HashRef',
  default => sub { +{} },
);

=attr hasher

B<Type:> Object (must fulfill role L<Crypt::PBKDF2::Hash>), B<Default:> None.

It is also possible to provide a hash object directly; in this case the
C<hash_class> and C<hash_args> are ignored.

=cut

has hasher => (
  is => 'ro',
  isa => role_type('Crypt::PBKDF2::Hash'),
  lazy_build => 1,
);

method _build_hasher {
  my $class = $self->hash_class;
  if ($class !~ s/^\+//) {
    $class = "Crypt::PBKDF2::Hash::$class";
  }
  my $hash_args = $self->hash_args;

  Class::MOP::load_class($class);
  return $class->new( %$hash_args );
}

=attr iterations

B<Type:> Integer, B<Default:> 1000.

The default number of iterations of the hashing function to use for the
C<generate> and C<PBKDF2> methods.

=cut

has iterations => (
  is => 'ro',
  isa => 'Int',
  default => '1000',
);

=attr output_len

B<Type:> Integer.

The default size (in bytes, not bits) of the output hash. If a value isn't
provided, the output size depends on the C<hash_class>S< / >C<hasher>
selected, and will equal the output size of the backend hash (e.g. 20 bytes
for HMACSHA1).

=cut

has output_len => (
  is => 'ro',
  isa => 'Int',
);

=attr salt_len

B<Type:> Integer, B<Default:> 4

The default salt length (in bytes) for the C<generate> method.

=cut

has salt_len => (
  is => 'ro',
  isa => 'Int',
  default => 4,
);

method _random_salt {
  my $ret = "";
  for my $n (1 .. $self->salt_len) {
    $ret .= chr(int rand 256);
  }
  return $ret;
}

=method generate ($password, [$salt])

Generates a hash for the given C<$password>. If C<$salt> is not provided,
a random salt with length C<salt_len> will be generated.

The output looks something like the following (generated with the HMACSHA1
hash, at the default 1000 iterations and default output length):

    $PBKDF2$HMACSHA1:1000:akrvug==$Zi+c82tnjpcrRmUAHRd8h4ZRR5M=

The format has been chosen to be broadly similar to that used by C<crypt()>,
only with somewhat more structured information in the second (salt) field.

=cut

method generate ($password, $salt) {
  $salt = $self->_random_salt unless defined $salt;

  my $hash = $self->PBKDF2($salt, $password);
  return $self->encode_string($salt, $hash);
}

=method validate ($hashed, $password)

Validates whether the password C<$password> matches the hash string
C<$hashed>. May throw an exception if the format of C<$hashed> is invalid;
otherwise, returns true or false.

=cut

method validate ($hashed, $password) {
  my $info = $self->decode_string($hashed);

  my $hasher = try {
    $self->hasher_from_algorithm($info->{algorithm});
  } catch {
    croak "Couldn't construct hasher for ''$info->{algorithm}'': $_";
  };

  my $checker = $self->clone(
    hasher => $hasher,
    iterations => $info->{iterations},
    output_len => length($info->{hash}),
  );

  my $check_hash = $checker->PBKDF2($info->{salt}, $password);

  return ($check_hash eq $info->{hash});
}

=method PBKDF2 ($salt, $password)

The raw PBKDF2 algorithm. Given the C<$salt> and C<$password>, returns the
raw binary hash.

=cut

method PBKDF2 ($salt, $password) {
  my $iterations = $self->iterations;
  my $hasher = $self->hasher;
  my $output_len = $self->output_len || $hasher->hash_len;

  my $hLen = $hasher->hash_len;
  my $l = int($output_len / $hLen);
  my $r = $output_len % $hLen;

  if ($l > 0xffffffff or $l == 0xffffffff && $r > 0) {
    croak "output_len too large for PBKDF2";
  }

  my $output;

  for my $i (1 .. $l) {
    $output .= $self->_PBKDF2_F($hasher, $salt, $password, $iterations, $i);
  }

  if ($r) {
    $output .= substr( $self->_PBKDF2_F($hasher, $salt, $password, $iterations, $l + 1), 0, $r);
  }

  return $output;
}

=method PBKDF2_base64 ($salt, $password)

As the C<PBKDF2> method, only the output is encoded with L<MIME::Base64>.

=cut

sub PBKDF2_base64 {
  my $self = shift;

  return MIME::Base64::encode( $self->PBKDF2(@_), "" );
}

=method PBKDF2_hex ($salt, $password)

As the C<PBKDF2> method, only the output is encoded in hexadecimal.

=cut

sub PBKDF2_hex {
  my $self = shift;
  return unpack "H*", unpack "A*", $self->PBKDF2(@_);
}

method _PBKDF2_F ($hasher, $salt, $password, $iterations, $i) {
  my $result = 
  my $hash = 
    $hasher->generate( $salt . pack("N", $i), $password );

  for my $iter (2 .. $iterations) {
    $hash = $hasher->generate( $hash, $password );
    $result ^= $hash;
  }

  return $result;
}

=method encode_string ($salt, $hash)

Given a generated salt and hash, hash, generates output in the form generated by
C<generate> and accepted by C<validate>. Unlikely to be of much use to anyone
else.

=cut

method encode_string ($salt, $hash) {
  my $hasher = $self->hasher;
  my $hasher_class = Class::MOP::class_of($hasher)->name;
  if (!defined $hasher_class || $hasher_class !~ s/^Crypt::PBKDF2::Hash:://) {
    croak "Can't ''encode_string'' with a hasher class outside of Crypt::PBKDF2::Hash::*";
  }

  my $algo_string = $hasher->to_algo_string;
  $algo_string = defined($algo_string) ? "{$algo_string}" : "";

  return '$PBKDF2$' . "$hasher_class$algo_string:" . $self->iterations . ':'
  . MIME::Base64::encode($salt, "") . '$'
  . MIME::Base64::encode($hash, "");
}

=method decode_string ($hashed)

Given a textual hash in the form generated by C<generate>, decodes it and
returns a HashRef containing:

=over 4

=item *

C<algorithm>: A string representing the hash algorithm used. See
L</hasher_from_algorithm ($algo_str)>.

=item *

C<iterations>: The number of iterations used.

=item *

C<salt>: The salt, in raw binary form.

=item *

C<hash>: The hash, in raw binary form.

=back

This method is mostly for internal use, but it has been left public as it
may come in handy. If the input data is invalid, this method may throw an
exception.

=cut

method decode_string ($hashed) {
  if ($hashed !~ /^\$PBKDF2\$/) {
    croak "Unrecognized hash";
  }

  if (my ($algorithm, $iterations, $salt, $hash) = $hashed =~ 
      /^\$PBKDF2\$([^:}]+(?:\{[^}]+\})?):(\d+):([^\$]+)\$(.*)/) {
    return {
      algorithm => $algorithm,
      iterations => $iterations,
      salt => MIME::Base64::decode($salt),
      hash => MIME::Base64::decode($hash),
    }
  } else {
    croak "Invalid format";
  }
}

=method hasher_from_algorithm ($algo_str)

Attempts to load and instantiate a C<Crypt::PBKDF2::Hash::*> class based on
an algorithm string as produced by C<encode_string> / C<generate>.

=cut

method hasher_from_algorithm ($algo_str) {
  if ($algo_str =~ s/\{([^}]+)\}$//) {
    my $args = $1;
    Class::MOP::load_class( "Crypt::PBKDF2::Hash::$algo_str" );
    return "Crypt::PBKDF2::Hash::$algo_str"->from_algo_string($args);
  } else {
    Class::MOP::load_class( "Crypt::PBKDF2::Hash::$algo_str" );
    return "Crypt::PBKDF2::Hash::$algo_str"->new;
  }
}

=method clone (%params)

Create a new object like this one, but with C<%params> changed.

=cut

__PACKAGE__->meta->make_immutable;
1;

=pod

=head1 SYNOPSIS

    use Crypt::PBKDF2;

    my $pbkdf2 = Crypt::PBKDF2->new(
        hash_class => 'HMACSHA1' # this is the default
        iterations => 1000,      # so is this
        output_len => 20,        # and this
        salt_len => 4,           # and this.
    );

    my $hash = $pbkdf2->generate("s3kr1t_password");
    if ($pbkdf2->validate($hash, "s3kr1t_password")) {
        access_granted();
    }

=head1 DESCRIPTION

PBKDF2 is a secure password hashing algorithm that uses the techniques of
"key strengthening" to make the complexity of a brute-force attack
arbitrarily high. PBKDF2 uses any other cryptographic hash or cipher (by
convention, usually HMAC-SHA1, but C<Crypt::PBKDF2> is fully pluggable), and
allows for an arbitrary number of iterations of the hashing function, and a
nearly unlimited output hash size (up to 2**32 - 1 times the size of the
output of the backend hash). The hash is salted, as any password hash should
be, and the salt may also be of arbitrary size.

=head1 SEE ALSO

=over 4

=item *

B<Wikipedia: PBKDF2>: L<http://en.wikipedia.org/wiki/PBKDF2>

=item *

B<RFC2898, PKCS#5 version 2.0>: L<http://tools.ietf.org/html/rfc2898>

=back
