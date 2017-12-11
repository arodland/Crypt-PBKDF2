package Crypt::PBKDF2; 
# ABSTRACT: The PBKDF2 password hashing algorithm.
# VERSION
# AUTHORITY
use Moo 2;
use strictures 2;
use namespace::autoclean;
use MIME::Base64 ();
use Carp qw(croak);
use Module::Runtime;
use Try::Tiny;
use Type::Tiny;
use Types::Standard 1.000005 qw(Str Int HashRef ConsumerOf);
use Scalar::Util qw(blessed);

sub BUILD {
  my ($self) = @_;
  $self->hasher; # Force instantiation, so we get errors ASAP
}

=attr hash_class

B<Type:> String, B<Default:> HMACSHA1

The name of the default class that will provide PBKDF2's Pseudo-Random
Function (the backend hash). If the value starts with a C<+>, the C<+> will
be removed and the remainder will be taken as a fully-qualified package
name. Otherwise, the value will be appended to C<Crypt::PBKDF2::Hash::>.

=cut

has hash_class => (
  is => 'ro',
  isa => Str,
  default => 'HMACSHA1',
  predicate => 'has_hash_class',
);

=attr hash_args

B<Type:> HashRef, B<Default:> {}

Arguments to be passed to the C<hash_class> constructor.

=cut

has hash_args => (
  is => 'ro',
  isa => HashRef,
  default => sub { +{} },
  predicate => 'has_hash_args',
);

=attr hasher

B<Type:> Object (must fulfill role L<Crypt::PBKDF2::Hash>), B<Default:> None.

It is also possible to provide a hash object directly; in this case the
C<hash_class> and C<hash_args> are ignored.

=cut

has hasher => (
  is => 'ro',
  isa => ConsumerOf['Crypt::PBKDF2::Hash'],
  lazy => 1,
  default => sub { shift->_lazy_hasher },
);

has _lazy_hasher => (
  is => 'ro',
  isa => ConsumerOf['Crypt::PBKDF2::Hash'],
  lazy => 1,
  init_arg => undef,
  predicate => 'has_lazy_hasher',
  builder => '_build_hasher',
);

sub _build_hasher {
  my ($self) = @_;
  my $class = $self->hash_class;
  if ($class !~ s/^\+//) {
    $class = "Crypt::PBKDF2::Hash::$class";
  }
  my $hash_args = $self->hash_args;

  return Module::Runtime::use_module($class)->new( %$hash_args );
}

=attr iterations

B<Type:> Integer, B<Default:> 1000.

The default number of iterations of the hashing function to use for the
C<generate> and C<PBKDF2> methods.

=cut

has iterations => (
  is => 'ro',
  isa => Int,
  default => 1000,
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
  isa => Int,
  predicate => 'has_output_len',
);

=attr salt_len

B<Type:> Integer, B<Default:> 4

The default salt length (in bytes) for the C<generate> method.

=cut

has salt_len => (
  is => 'ro',
  isa => Int,
  default => 4,
);

sub _random_salt {
  my ($self) = @_;
  my $ret = "";
  for my $n (1 .. $self->salt_len) {
    $ret .= chr(int rand 256);
  }
  return $ret;
}

=attr encoding

B<Type:> String (either "crypt" or "ldap"), B<Default:> "ldap"

The hash format to generate. The "ldap" format is intended to be compatible
with RFC2307, and looks like:

    {X-PBKDF2}HMACSHA1:AAAD6A:8ODUPA==:1HSdSVVwlWSZhbPGO7GIZ4iUbrk=

While the "crypt" format is similar to the format used by the C<crypt()>
function, except with more structured information in the second (salt) field.
It looks like:

    $PBKDF2$HMACSHA1:1000:4q9OTg==$9Pb6bCRgnct/dga+4v4Lyv8x31s=

Versions of this module up to 0.110461 generated the "crypt" format, so set
that if you want it. Current versions of this module will read either format,
but the "ldap" format is preferred.

=cut

has encoding => (
  is => 'ro',
  isa => Str,
  default => 'ldap',
);

=attr length_limit

B<Type:> Integer

The maximum password length to allow, for generate and verify functions.
Allowing passwords of unlimited length can allow a denial-of-service attack
in which an attacker asks the server to validate very large passwords.

For compatibility this attribute is unset by default, but it is recommended
to set it to a reasonably small value like 100 -- large enough that users
aren't discouraged from having secure passwords, but small enough to limit
the computation needed to validate any one password.

=cut

has length_limit => (
  is => 'ro',
  isa => Int,
  predicate => 'has_length_limit',
);

=method generate ($password, [$salt])

Generates a hash for the given C<$password>. If C<$salt> is not provided,
a random salt with length C<salt_len> will be generated.

There are two output formats available, depending on the setting of the
C<encoding> attribute: "ldap" and "crypt"; see the documentation for
L</encoding> for more information.

=cut

sub generate {
  my ($self, $password, $salt) = @_;
  $salt = $self->_random_salt unless defined $salt;

  if ($self->has_length_limit and length($password) > $self->length_limit) {
    croak "Password exceeds length limit";
  }

  my $hash = $self->PBKDF2($salt, $password);
  return $self->encode_string($salt, $hash);
}

=method validate ($hashed, $password)

Validates whether the password C<$password> matches the hash string
C<$hashed>. May throw an exception if the format of C<$hashed> is invalid;
otherwise, returns true or false. Accepts both formats that the "generate"
method can produce.

=cut

# no-shortcut version of eq
sub _is_equal {
  my ($x, $y) = @_;

  my $length_check = length($x) == length($y);

  my $result = 0;
  my @x = split //, $x;
  my @y = split //, $y;
  for my $char_x (@x) {
    my $char_y = shift @y;
    {
      no warnings "uninitialized";
      $result |= ord($char_x) ^ ord($char_y);
    }
  }
  my $eq_check = $result == 0;

  return $length_check & $eq_check;
}

sub validate {
  my ($self, $hashed, $password) = @_;

  if ($self->has_length_limit and length($password) > $self->length_limit) {
    croak "Password exceeds length limit";
  }

  my $info = $self->decode_string($hashed);

  my $hasher = try {
    $self->hasher_from_algorithm($info->{algorithm}, $info->{algorithm_options});
  } catch {
    my $opts = defined($info->{algorithm_options}) ? " (options ''$info->{algorithm_options}'')" : "";
    croak "Couldn't construct hasher for ''$info->{algorithm}''$opts: $_";
  };

  my $checker = $self->clone(
    hasher => $hasher,
    iterations => $info->{iterations},
    output_len => length($info->{hash}),
  );

  my $check_hash = $checker->PBKDF2($info->{salt}, $password);

  # help mitigate timing attacks by taking no shortcuts when comparing
  # two hashes (eq will stop when they are no longer equal)
  return _is_equal($check_hash, $info->{hash});
}

=method PBKDF2 ($salt, $password)

The raw PBKDF2 algorithm. Given the C<$salt> and C<$password>, returns the
raw binary hash.

=cut

sub PBKDF2 {
  my ($self, $salt, $password) = @_;
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
  return unpack "H*", $self->PBKDF2(@_);
}

sub _PBKDF2_F {
  my ($self, $hasher, $salt, $password, $iterations, $i) = @_;
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

sub encode_string {
  my ($self, $salt, $hash) = @_;
  if ($self->encoding eq 'crypt') {
    return $self->_encode_string_cryptlike($salt, $hash);
  } elsif ($self->encoding eq 'ldap') {
    return $self->_encode_string_ldaplike($salt, $hash);
  } else {
    die "Unknown setting '", $self->encoding, "' for encoding";
  }
}

sub _encode_string_cryptlike {
  my ($self, $salt, $hash) = @_;
  my $hasher = $self->hasher;
  my $hasher_class = blessed($hasher);
  if (!defined $hasher_class || $hasher_class !~ s/^Crypt::PBKDF2::Hash:://) {
    croak "Can't ''encode_string'' with a hasher class outside of Crypt::PBKDF2::Hash::*";
  }

  my $algo_string = $hasher->to_algo_string;
  $algo_string = defined($algo_string) ? "{$algo_string}" : "";

  return '$PBKDF2$' . "$hasher_class$algo_string:" . $self->iterations . ':'
  . MIME::Base64::encode($salt, "") . '$'
  . MIME::Base64::encode($hash, "");
}

sub _encode_string_ldaplike {
  my ($self, $salt, $hash) = @_;
  my $hasher = $self->hasher;
  my $hasher_class = blessed($hasher);
  if (!defined $hasher_class || $hasher_class !~ s/^Crypt::PBKDF2::Hash:://) {
    croak "Can't ''encode_string'' with a hasher class outside of Crypt::PBKDF2::Hash::*";
  }

  my $algo_string = $hasher->to_algo_string;
  $algo_string = defined($algo_string) ? "+$algo_string" : "";

  return '{X-PBKDF2}' . "$hasher_class$algo_string:" 
  . $self->_b64_encode_int32($self->iterations) . ':'
  . MIME::Base64::encode($salt, "") . ':'
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

sub decode_string {
  my ($self, $hashed) = @_;
  if ($hashed =~ /^\$PBKDF2\$/) {
    return $self->_decode_string_cryptlike($hashed);
  } elsif ($hashed =~ /^\{X-PBKDF2}/i) {
    return $self->_decode_string_ldaplike($hashed);
  } else {
    croak "Unrecognized hash";
  }
}

sub _decode_string_cryptlike {
  my ($self, $hashed) = @_;
  if ($hashed !~ /^\$PBKDF2\$/) {
    croak "Unrecognized hash";
  }

  if (my ($algorithm, $opts, $iterations, $salt, $hash) = $hashed =~
      /^\$PBKDF2\$([^:}]+)(?:\{([^}]+)\})?:(\d+):([^\$]+)\$(.*)/) {
    return {
      algorithm => $algorithm,
      algorithm_options => $opts,
      iterations => $iterations,
      salt => MIME::Base64::decode($salt),
      hash => MIME::Base64::decode($hash),
    }
  } else {
    croak "Invalid format";
  }
}

sub _decode_string_ldaplike {
  my ($self, $hashed) = @_;
  if ($hashed !~ /^\{X-PBKDF2}/i) {
    croak "Unrecognized hash";
  }

  if (my ($algo_str, $iterations, $salt, $hash) = $hashed =~
      /^\{X-PBKDF2}([^:]+):([^:]{6}):([^\$]+):(.*)/i) {
    my ($algorithm, $opts) = split /\+/, $algo_str;
    return {
      algorithm => $algorithm,
      algorithm_options => $opts,
      iterations => $self->_b64_decode_int32($iterations),
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

sub hasher_from_algorithm {
  my ($self, $algorithm, $args) = @_;
  my $class = Module::Runtime::use_module("Crypt::PBKDF2::Hash::$algorithm");

  if (defined $args) {
    return $class->from_algo_string($args);
  } else {
    return $class->new;
  }
}

=method clone (%params)

Create a new object like this one, but with C<%params> changed.

=cut

sub clone {
  my ($self, %params) = @_;
  my $class = ref $self;

  # If the hasher was built from hash_class and hash_args, then omit it from
  # the clone. But if it was set by the user, then we need to copy it. We're
  # assuming that the hasher has no state, so it doesn't need a deep clone.
  # This is true of all of the ones that I'm shipping, but if it's not true for
  # you, let me know.

  my %new_args = (
    $self->has_hash_class  ? (hash_class  => $self->hash_class) : (),
    $self->has_hash_args   ? (hash_args   => $self->hash_args)  : (),
    $self->has_output_len  ? (output_len  => $self->output_len) : (),
    $self->has_lazy_hasher ? () : (hasher => $self->hasher),
    iterations => $self->iterations,
    salt_len => $self->salt_len,
    %params,
  );
  
  return $class->new(%new_args);
}

sub _b64_encode_int32 {
  my ($self, $value) = @_;
  my $b64 = MIME::Base64::encode(pack("N", $value), "");
  $b64 =~ s/==$//;
  return $b64;
}

sub _b64_decode_int32 {
  my ($self, $b64) = @_;
  $b64 .= "==";
  return unpack "N", MIME::Base64::decode($b64);
}

__PACKAGE__->meta->make_immutable;
1;

=pod

=head1 SYNOPSIS

    use Crypt::PBKDF2;

    my $pbkdf2 = Crypt::PBKDF2->new(
        hash_class => 'HMACSHA1', # this is the default
        iterations => 1000,       # so is this
        output_len => 20,         # and this
        salt_len => 4,            # and this.
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

=item *

B<RFC2307, Using LDAP as a Network Information Service>: 
L<http://tools.ietf.org/html/rfc2307>

=back
