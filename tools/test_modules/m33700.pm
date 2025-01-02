#!/usr/bin/env perl

##
## Author......: See docs/credits.txt
## License.....: MIT
##

use strict;
use warnings;

use Crypt::Mode::CBC;
use Crypt::PBKDF2;

sub module_constraints { [[0, 256], [0, 256], [-1, -1], [-1, -1], [-1, -1]] }

sub module_generate_hash
{
  my $word = shift;
  my $salt = shift;

  my $signature = 'samourai';
  my $plaintext = '{"wallet":{"test';
  my $iterations = 10000;
  my $key_length = 48;

  my $pbkdf2 = Crypt::PBKDF2->new(
    hash_class => 'HMACSHA2',
    hash_args  => { sha_size => 256 },
    iterations => $iterations,
    output_len => $key_length,
  );

  my $derived_key = $pbkdf2->PBKDF2($salt, $word);
  my $aes_key = substr($derived_key, 0, 32);
  my $aes_iv  = substr($derived_key, 32, 16);

  my $cbc = Crypt::Mode::CBC->new('AES');
  my $ciphertext = $cbc->encrypt($plaintext, $aes_key, $aes_iv);

  my $salt_hex = pack('H*', $salt);
  my $ciphertext_hex = pack('H*', $ciphertext);

  my $hash = sprintf ('%s:%s:%s', $signature, $salt_hex, $ciphertext_hex);

  return $hash;
}

sub module_verify_hash
{
  my $line = shift;

  my ($signature, $salt, $hash, $word) = split (':', $line);

  return unless defined $signature;
  return unless defined $salt;
  return unless defined $hash;
  return unless defined $word;

  my $word_packed = pack_if_HEX_notation ($word);

  my $new_hash = module_generate_hash ($word_packed, $salt);

  return ($new_hash, $word);
}

1;
