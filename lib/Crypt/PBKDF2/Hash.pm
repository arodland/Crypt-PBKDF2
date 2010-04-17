package Crypt::PBKDF2::Hash;

use Moose::Role;
use namespace::autoclean;

requires 'hash_len';

requires 'generate';

requires 'to_algo_string';

requires 'from_algo_string';

1;
