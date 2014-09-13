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
    # @param opts [Hash]
    # @option opts :group [ECDSA::Group]
    # @option opts :hash_algorithm [#digest]
    def initialize(key_image, c_array, r_array, opts = {})
      @group = opts.delete(:group) { RingSig.default_group }
      @hash_algorithm = opts.delete(:hash_algorithm) { RingSig.default_hash_algorithm }
      raise ArgumentError, "Unknown opts: #{opts.keys.join(', ')}" unless opts.empty?

      @key_image, @c_array, @r_array = key_image, c_array, r_array
      key_image.is_a?(ECDSA::Point) or raise ArgumentError, 'key_image is not an ECDSA::Point.'
      c_array.is_a?(Array) or raise ArgumentError, 'c_array is not an array.'
      r_array.is_a?(Array) or raise ArgumentError, 'r_array is not an array.'

      @hasher = Hasher.new(group: group, hash_algorithm: hash_algorithm)
    end

    # Creates a new instance of {Signature} from a der string.
    #
    # @param der_string [String]
    # @param opts [Hash]
    # @option opts :group [ECDSA::Group]
    # @option opts :hash_algorithm [#digest]
    # @return [Signature]
    def self.from_der(der_string, opts = {})
      group = opts.delete(:group) { RingSig.default_group }
      hash_algorithm = opts.delete(:hash_algorithm) { RingSig.default_hash_algorithm }
      raise ArgumentError, "Unknown opts: #{opts.keys.join(', ')}" unless opts.empty?

      asn1 = OpenSSL::ASN1.decode(der_string)

      key_image = ECDSA::Format::PointOctetString.decode(asn1.value[0].value, group)
      c_array = asn1.value[1].value.map{|i| i.value.to_i}
      r_array = asn1.value[2].value.map{|i| i.value.to_i}

      Signature.new(key_image, c_array, r_array, group: group, hash_algorithm: hash_algorithm)
    end

    # Creates a new instance of {Signature} from a hex string.
    #
    # @param hex_string [String]
    # @param opts [Hash]
    # @option opts :group [ECDSA::Group]
    # @option opts :hash_algorithm [#digest]
    # @return [Signature]
    def self.from_hex(hex_string, opts = {})
      group = opts.delete(:group) { RingSig.default_group }
      hash_algorithm = opts.delete(:hash_algorithm) { RingSig.default_hash_algorithm }
      raise ArgumentError, "Unknown opts: #{opts.keys.join(', ')}" unless opts.empty?

      Signature.from_der([hex_string].pack('H*'), group: group, hash_algorithm: hash_algorithm)
    end

    # Encodes this signature into a der string. The encoded data contains
    # the key_image, c_array, and r_array. It does not contain the group
    # or hash_algorithm.
    #
    # @param opts [Hash]
    # @option opts :compression [Boolean]
    # @return [String]
    def to_der(opts = {})
      compression = opts.delete(:compression) { true }
      raise ArgumentError, "Unknown opts: #{opts.keys.join(', ')}" unless opts.empty?

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
    # @param opts [Hash]
    # @option opts :compression [Boolean]
    # @return [String]
    def to_hex(opts = {})
      compression = opts.delete(:compression) { true }
      raise ArgumentError, "Unknown opts: #{opts.keys.join(', ')}" unless opts.empty?

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
