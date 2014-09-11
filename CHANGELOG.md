Change log
====

This gem follows [Semantic Versioning 2.0.0](http://semver.org/spec/v2.0.0.html).
All classes and public methods are part of the public API, unless explicitly
noted otherwise in their documentation.

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

- All core functionality is implemented:
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
