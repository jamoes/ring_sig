module RingSig
  # Instances of this class represent RingSig signatures.
  class Signature
    # @return [ECDSA::Point]
    attr_reader :key_image

    # @return [Array]
    attr_reader :c_array

    # @return [Array]
    attr_reader :r_array

    # @return [ECDSA::Group]
    attr_reader :group

    # @return [#digest]
    attr_reader :hash_algorithm

    # Creates a new instance of {Signature}.
    #
    # @param key_image [ECDSA::Point]
    # @param c_array [Array<Integer>]
    # @param r_array [Array<Integer>]
    # @param group [ECDSA::Group]
    # @param hash_algorithm [#digest]
    def initialize(key_image, c_array, r_array, group: ECDSA::Group::Secp256k1, hash_algorithm: OpenSSL::Digest::SHA256)
      @key_image, @c_array, @r_array = key_image, c_array, r_array
      key_image.is_a?(ECDSA::Point) or raise ArgumentError, 'key_image is not an ECDSA::Point.'
      c_array.is_a?(Array) or raise ArgumentError, 'c_array is not an array.'
      r_array.is_a?(Array) or raise ArgumentError, 'r_array is not an array.'

      @group = group
      @hash_algorithm = hash_algorithm
      @hasher = Hasher.new(group, hash_algorithm)
    end

    # Creates a new instance of {Signature} from a der string.
    #
    # @param der_string [String]
    # @param group [ECDSA::Group]
    # @param hash_algorithm [#digest]
    # @return [Signature]
    def self.from_der(der_string, group: ECDSA::Group::Secp256k1, hash_algorithm: OpenSSL::Digest::SHA256)
      asn1 = OpenSSL::ASN1.decode(der_string)

      key_image = ECDSA::Format::PointOctetString.decode(asn1.value[0].value, group)
      c_array = asn1.value[1].value.map{|i| i.value.to_i}
      r_array = asn1.value[2].value.map{|i| i.value.to_i}

      Signature.new(key_image, c_array, r_array, group: group, hash_algorithm: hash_algorithm)
    end

    # Creates a new instance of {Signature} from a hex string.
    #
    # @param hex_string [String]
    # @param group [ECDSA::Group]
    # @param hash_algorithm [#digest]
    # @return [Signature]
    def self.from_hex(hex_string, group: ECDSA::Group::Secp256k1, hash_algorithm: OpenSSL::Digest::SHA256)
      Signature.from_der([hex_string].pack('H*'), group: group, hash_algorithm: hash_algorithm)
    end

    # Encodes this signature into a der string. The encoded data contains
    # the key_image, c_array, and r_array. It does not contain the group
    # or hash_algorithm.
    #
    # @param compression [Boolean]
    # @return [String]
    def to_der(compression: true)
      OpenSSL::ASN1::Sequence.new([
        OpenSSL::ASN1::OctetString.new(ECDSA::Format::PointOctetString.encode(key_image, compression: compression)),
        OpenSSL::ASN1::Sequence.new(c_array.map{|i| OpenSSL::ASN1::Integer.new(i)}),
        OpenSSL::ASN1::Sequence.new(r_array.map{|i| OpenSSL::ASN1::Integer.new(i)}),
      ]).to_der
    end

    # Encodes this signature into a hex string. The encoded data contains
    # the key_image, c_array, and r_array. It does not contain the group
    # or hash_algorithm.
    #
    # @param compression [Boolean]
    # @return [String]
    def to_hex(compression: true)
      to_der(compression: compression).unpack('H*').first
    end

    # Verifies this signature against an ordered set of public keys.
    #
    # @param message [String]
    # @param public_keys [Array<PublicKey>]
    # @return [Boolean] true if the signature verifies, false otherwise.
    def verify(message, public_keys)
      ll_array = []
      rr_array = []

      public_keys.each_with_index do |k, i|
        ll_array[i] = (group.generator * r_array[i]) + (k.point * c_array[i])
        rr_array[i] = (@hasher.hash_point(k.point) * (r_array[i]) + key_image * c_array[i])
      end

      c_sum = c_array.inject{|a, b| a + b} % group.order

      message_digest = @hasher.hash_string(message)
      challenge = @hasher.hash_array([message_digest] + ll_array + rr_array)

      c_sum == challenge
    end

    # Returns an array containing key image coordinates, c_array, and r_array.
    # @return (Array)
    def components
      key_image.coords + c_array + r_array
    end
  end
end
