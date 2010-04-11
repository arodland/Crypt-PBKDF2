package Crypt::PBKDF2;
use Moose;
use MooseX::Method::Signatures;

use Digest::SHA ();
use MIME::Base64 ();
use Carp qw(croak cluck);

has algorithm => (
  is => 'rw',
  isa => 'Str',
  default => 'HMAC-SHA-1'
);

method _shasize ($algorithm) {
  if ($algorithm eq "HMAC-SHA-2") { # Someone might call SHA-256 SHA-2.
    self->algorithm($algorithm = "HMAC-SHA-256");
  }

  if ($algorithm =~ /^HMAC-SHA-?(\d+)$/) {
    my $shasize = $1;

    return $shasize if grep $_ == $shasize, (1, 224, 256, 384, 512);
    croak "What is SHA-$shasize?";
  } else {
    croak "Algorithms other than HMAC-SHA-{1, 224, 256, 384, 512} are currently unsupported.";
  }
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

method hLen ($algorithm) {
  my $shasize = $self->_shasize($algorithm);
  if ($shasize == 1) {
    return 20;
  } else {
    return $shasize / 8;
  }
}

has output_len => (
  is => 'ro',
  isa => 'Int',
  lazy => 1,
  default => method {
    $self->hLen( $self->algorithm );
  },
);

method hasher_for_sha ($shasize) {
  my $hasher = Digest::SHA->can("hmac_sha$shasize");
  croak "Can't figure out how to hash SHA-$shasize" unless defined $hasher;
  return $hasher;
}

method hasher ($algorithm) {
  my $shasize = $self->_shasize($algorithm);
  return $self->hasher_for_sha($shasize);
}

method random_salt {
  my $ret = "";
  for my $n (1 .. $self->salt_len) {
    $ret .= chr(int rand 256);
  }
  return $ret;
}

sub _hexdump {
  unpack "H*", unpack "A*", shift;
}

method encode_string ($salt, $hash) {
  return '$PBKDF2$' . $self->algorithm . ':' . $self->iterations . ':' 
  . MIME::Base64::encode($salt, "") . '$'
  . MIME::Base64::encode($hash);
}

method decode_string ($hashed) {
  if ($hashed !~ /^\$PBKDF2\$/) {
    croak "Unrecognized hash";
  }

  if (my ($algorithm, $iterations, $salt, $hash) = $hashed =~ /^\$PBKDF2\$([^:]+):(\d+):([^\$]+)\$(.*)/) {
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

method generate ($password, :$salt, :$iterations, :$algorithm, :$output_len) {
  $salt = $self->random_salt unless defined $salt;

  my $hash = $self->PBKDF2($salt, $password, 
    $iterations ? (iterations => $iterations) : (),
    $algorithm ? (algorithm => $algorithm) : (),
    $output_len ? (output_len => $output_len) : (),
  );
  return $self->encode_string($salt, $hash);
}

method validate ($hashed, $password) {
  my $info = $self->decode_string($hashed);

  my $check_hash = $self->PBKDF2(
    $info->{salt}, $password, 
    iterations => $info->{iterations},
    algorithm => $info->{algorithm},
    output_len => length($info->{hash}),
  );
  return ($check_hash eq $info->{hash});
}

method PBKDF2_F ($hasher, $salt, $password, $iterations, $i) {
  my $result = 
  my $hash = 
    $hasher->( $salt . pack("N", $i), $password );

  for my $iter (2 .. $iterations) {
    $hash = $hasher->( $hash, $password );
    $result ^= $hash;
  }

  return $result;
}

method PBKDF2 ($salt, $password, :$iterations, :$algorithm, :$output_len) {
  $iterations ||= $self->iterations;
  $algorithm ||= $self->algorithm;
  $output_len ||= $self->output_len;

  my $hasher = $self->hasher($algorithm);
  my $hLen = $self->hLen($algorithm);

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


1;
