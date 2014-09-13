require 'openssl'
require 'ecdsa'
require 'ring_sig/hasher'
require 'ring_sig/private_key'
require 'ring_sig/public_key'
require 'ring_sig/signature'
require 'ring_sig/version'
require 'ring_sig/ecdsa/point'

# The top-level module for the RingSig gem.
module RingSig
  class << self
    # @return [ECDSA::Group] the default group. This group will be used in any
    #   method in the RingSig library that calls for a group, if none is
    #   specified. Starts as `ECDSA::Group::Secp256k1`.
    attr_accessor :default_group

    # @return [#digest] the default hash algorithm. This hash algorithm will be
    #   used in any method in the RingSig library that calls for a hash
    #   algorithm, if none is specified. Starts as `OpenSSL::Digest::SHA256`.
    attr_accessor :default_hash_algorithm
  end

  self.default_group = ECDSA::Group::Secp256k1
  self.default_hash_algorithm = OpenSSL::Digest::SHA256
end
