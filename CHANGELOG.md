Change log
====

This gem follows [Semantic Versioning 2.0.0](http://semver.org/spec/v2.0.0.html).
All classes and public methods are part of the public API, unless explicitly
noted otherwise in their documentation.

0.4.0
----
Release on 2014-09-18

This release maintains API compatibility with version 0.3.0, except for the two
constants that were removed.

Signatures produced with prior versions may be incompatible with signatures from
this version.

- Change the `Hasher#hash_string` method so that it can handle ECDSA groups
  that have a much smaller order than the number of bits they have (such as
  Curve25519).
- `Hasher` now validates that its group's byte-length is equal to its hash
  algorithm's byte-length.
- Remove support for ECDSA groups that have an order larger than the number of
  bits they have. Secp160k1 and Secp160r1 fall into this category because their
  order is larger than 2^160.
- Remove the `Secp160k1_Ripemd160` and `Secp160r1_Ripemd160` constants, since
  their groups are no longer supported.

0.3.0
----
Released on 2014-09-15

This release breaks API compatibility with version 0.2.0.

- Change `PrivateKey`, `PublicKey`, and `Signature` constructors such that they
  accept a required `Hasher` argument rather than an optional `ECDSA::Group` and
  `hash_algorithm`. The `Hasher` encapsulates these properties.
- Change `Hasher` constructor so that `group` and `hash_algorithm` attributes
  are passed in as explicit arguments rather than options.
- Remove `RingSig.default_group` and `RingSig.defaut_hash_algorithm` attributes.
  There are now no default algorithms.
- Update gem dependency for `ecdsa` gem to 1.2.

This will hopefully be the last major API change for a while, but it still may
change until 1.0 is released.

0.2.0
----
Released on 2014-09-12

This release breaks API compatibility with version 0.1.0.

- Add support for ruby 1.9, including jruby-19mode.
- Add `RingSig.default_group` and `RingSig.defaut_hash_algorithm` attributes.
- Change `Hasher` constructor so that `group` and `hash_algorithm` attributes
  are passed in as options rather than explicit arguments.


0.1.0
----
Released on 2014-09-11

This release breaks API compatibility with version 0.0.1.

- Split the `Key` class into `PrivateKey` and `PublicKey`, which better
  encapsulate the functionality of each.
- The `sign` and `key_image` methods are placed in the `PrivateKey` class.
- Remove the `drop_private_key` method from `Key`. Instead, a new method simply
  called `public_key` is included in both `PrivateKey` and `PublicKey`.
- Add methods `to_hex`, `to_octet`, `from_hex`, and `from_octet` to both
  `PrivateKey` and `PublicKey` classes.
- Add `==` methods to `PrivateKey` and `PublicKey`
- Add `point` attribute to `PublicKey` which stores the actual public key.
- Add `point` method to `PrivateKey` which references the public key's point.
- Add `value` attribute to `PrivateKey` which stores the actual private key.

0.0.1
----
Released on 2014-09-09

All core functionality is implemented:

- `Key` class
  - `sign` method
  - `key_image` method
  - `drop_private_key` method
  - `public_key` and `private_key` attributes
  - `group` and `hash_algorithm` attributes
- `Signature` class
  - `verify` method
  - `components` method
  - `to_hex`, `to_der`, `from_hex`, and `from_der` methods
  - `key_image`, `c_array`, and `r_array` attributes
  - `group` and `hash_algorithm` attributes
- `Hasher` class
  - `hash_string` method
  - `hash_array` method
  - `hash_point` method
  - `shuffle` method
  - `group` and `algorithm` attributes
