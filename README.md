# RingSig gem for Ruby

[![Build Status](https://travis-ci.org/jamoes/ring_sig.svg?branch=master)](https://travis-ci.org/jamoes/ring_sig)

This gem implements a signature scheme known as one-time ring signatures.
The algorithm for one-time ring signatures was originally described in section
4.4 of the [CryptoNote Whitepaper](https://cryptonote.org/whitepaper.pdf).

## Ring signatures

Ring signatures are a special type of digital signature that allows the signer
to achieve *unconditional unlinkability* between their signature and their
public key. Signers sign a message using their private key and an arbitrary set
of foreign public keys. Verifiers are given the full set of public keys that a
message was signed with. Verifiers can prove that *one* of the private keys
signed the message, but they cannot determine *which* private key was actually
used for signing.

The signatures produced by this gem are said to be *one-time* ring signatures,
because the signature includes a Key Image, which is the same for all messages
signed with the same private key. Therefore, if a signer signs multiple messages
with the same private key, the signatures can be linked.

This gem does not use any randomness. All the algorithms are deterministic, and
do not require any sort of external source of randomness. When signing, a seed
is computed from a hash of the message and the private key. That seed is used
along with the hash algorithm and a nonce anywhere the signing algorithm calls
for randomness. As a result, the same inputs will always generate the same
signature.

## Current limitations

- This gem is not optimized for speed. All elliptical curve arithmetic is
computed in pure ruby. As a result, the sign and verify operations are slow.
Future versions will hopefully be better optimized for speed.
- This gem was not written by a cryptography expert. It is provided "as is"
and it is the user's responsibility to make sure it will be suitable for the
desired purpose.

## Installation

This library is distributed as a gem named [ring_sig](https://rubygems.org/gems/ring_sig)
at RubyGems.org.  To install it, run:

    gem install ring_sig

## Usage

First, require the gem:
```ruby
require 'ring_sig'
```

Next, create a private key for signing. For our example, we'll just use the
private key `1`. In the wild, you'll want to utilize a securely generated key.
```ruby
key = RingSig::PrivateKey.new(1)
```

Next, access a set a foreign public keys for signing. To demonstrate that any
arbitrary keys can be used, we'll use the public keys from the coinbase
transactions of the first three blocks on the bitcoin blockchain.

```ruby
foreign_keys = %w{
    04678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb649f6bc3f4cef38c4f35504e51ec112de5c384df7ba0b8d578a4c702b6bf11d5f
    0496b538e853519c726a2c91e61ec11600ae1390813a627c66fb8be7947be63c52da7589379515d4e0a604f8141781e62294721166bf621e73a82cbf2342c858ee
    047211a824f55b505228e4c3d5194c1fcfaa15a456abdf37f9b9d97a4040afc073dee6c89064984f03385237d92167c13e236446b417ab79a0fcae412ae3316b77
  }.map {|s| RingSig::PublicKey.from_hex(s) }
```

Next, we sign the message. This will assign a `RingSig::Signature` to the `sig`
variable, and a deterministically shuffled Array of `RingSig::PublicKey`s to the
`public_keys` variable.
```ruby
sig, public_keys = key.sign("Hello World!", foreign_keys)
```

You can see the signature contents by using the `to_hex` method:
```ruby
puts sig.to_hex
```

Finally, verify the signature:
```ruby
sig.verify("Hello World!", public_keys)
```

By default, this gem uses SHA256 for its hash algorithm, and Secp256k1 for its
ECDSA group. You can specify alternates if you'd like:
```ruby
key = RingSig::PrivateKey.new(1, group: ECDSA::Group::Secp256r1, hash_algorithm: OpenSSL::Digest::RIPEMD160)
```

## Standards

There currently aren't any standards around Ring Signatures that I know of. This
gem attempts to make sensible choices such that the exact same algorithm can
easily be implemented in other languages.

I'd love to see standards emerge around this powerful cryptographic primitive.
If you have any feedback about how to make the implementation of the algorithms
in this gem more inter-operable with other systems, I'd love to hear it!

## Contributing

To submit a bug, please go to this gem's [github page](https://github.com/jamoes/ring_sig)
and create a new issue.

If you'd like to contribute code, these are the general steps:

1. Fork and clone the repository
2. Create your feature branch (`git checkout -b my-new-feature`)
3. Commit your changes (`git commit -a 'Added some feature'`)
4. Push to the branch (`git push origin my-new-feature`)
5. Create a Pull Request

Please make sure to write tests for your new code, and  follow the existing code
standards wherever possible.

## Credit

Special thanks to the authors of the very excellent [ECDSA](https://github.com/DavidEGrayson/ruby_ecdsa)
gem. Not only is it a dependency of this gem, I also used it to gain a
much better understanding of elliptical curve crypto, and used it as inspiration
for this gem.

## Supported platforms

Ruby 2.0.0 and above.

## Documentation

For complete documentation, see the [RingSig page on RubyDoc.info](http://rubydoc.info/gems/ring_sig).
