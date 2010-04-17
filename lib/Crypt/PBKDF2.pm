package Crypt::PBKDF2;
use Moose;
use MooseX::Method::Signatures;
use Moose::Util::TypeConstraints;
use namespace::autoclean;
use MIME::Base64 ();
use Carp qw(croak);
use Try::Tiny;

has hash_class => (
  is => 'ro',
  isa => 'Str',
  default => 'HMACSHA1',
);

has hash_args => (
  is => 'ro',
  isa => 'HashRef',
  default => sub { +{} },
);

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

has salt_len => (
  is => 'ro',
  isa => 'Int',
  default => 4,
);

has iterations => (
  is => 'ro',
  isa => 'Int',
  default => '1000',
);

has output_len => (
  is => 'ro',
  isa => 'Int',
  lazy => 1,
  default => method {
    $self->hasher->hash_len;
  },
);

method random_salt {
  my $ret = "";
  for my $n (1 .. $self->salt_len) {
    $ret .= chr(int rand 256);
  }
  return $ret;
}

method encode_string ($salt, $hash, $hasher) {
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

method generate ($password, :$salt, :$iterations, :$hasher, :$output_len) {
  $salt = $self->random_salt unless defined $salt;
  $hasher = $self->hasher unless defined $hasher;

  my $hash = $self->PBKDF2($salt, $password, 
    hasher => $hasher,
    $iterations ? (iterations => $iterations) : (),
    $output_len ? (output_len => $output_len) : (),
  );
  return $self->encode_string($salt, $hash, $hasher);
}

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

method validate ($hashed, $password) {
  my $info = $self->decode_string($hashed);

  my $hasher = try {
    $self->hasher_from_algorithm($info->{algorithm});
  } catch {
    croak "Couldn't construct hasher for ''$info->{algorithm}'': $_";
  };

  my $check_hash = $self->PBKDF2(
    $info->{salt}, $password, 
    iterations => $info->{iterations},
    hasher => $hasher,
    output_len => length($info->{hash}),
  );
  return ($check_hash eq $info->{hash});
}

method PBKDF2_F ($hasher, $salt, $password, $iterations, $i) {
  my $result = 
  my $hash = 
    $hasher->generate( $salt . pack("N", $i), $password );

  for my $iter (2 .. $iterations) {
    $hash = $hasher->generate( $hash, $password );
    $result ^= $hash;
  }

  return $result;
}

method PBKDF2 ($salt, $password, :$iterations, :$hasher, :$output_len) {
  $iterations ||= $self->iterations;
  $hasher ||= $self->hasher;
  $output_len ||= $self->output_len;

  my $hLen = $hasher->hash_len;
  my $l = int($output_len / $hLen);
  my $r = $output_len % $hLen;

  if ($l > 0xffffffff or $l == 0xffffffff && $r > 0) {
    croak "output_len too large for PBKDF2";
  }

  my $output;

  for my $i (1 .. $l) {
    $output .= $self->PBKDF2_F($hasher, $salt, $password, $iterations, $i);
  }

  if ($r) {
    $output .= substr( $self->PBKDF2_F($hasher, $salt, $password, $iterations, $l + 1), 0, $r);
  }

  return $output;
}

sub PBKDF2_base64 {
  my $self = shift;

  return MIME::Base64::encode( $self->PBKDF2(@_), "" );
}

sub PBKDF2_hex {
  my $self = shift;
  return unpack "H*", unpack "A*", $self->PBKDF2(@_);
}

__PACKAGE__->meta->make_immutable;
1;
