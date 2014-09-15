module RingSig
  # Instances of this class represent a public ECDSA key.
  class PublicKey

    # The elliptical curve point of this public key.
    #
    # @return [ECDSA::Point]
    attr_reader :point

    # @return [Hasher]
    attr_reader :hasher

    # Creates a new instance of {PublicKey}.
    #
    # @param point [ECDSA::Point]
    # @param hasher [Hasher]
    def initialize(point, hasher)
      raise ArgumentError, "Point is not an ECDSA::Point" unless point.is_a?(ECDSA::Point)
      raise ArgumentError, "Point is not on the group's curve" unless hasher.group.include?(point)

      @point = point
      @hasher = hasher
    end

    # Creates a new instance of {PublicKey} from a hex string.
    #
    # @param hex_string [String]
    # @param hasher [Hasher]
    # @return [PublicKey]
    def self.from_hex(hex_string, hasher)
      self.from_octet([hex_string].pack('H*'), hasher)
    end

    # Creates a new instance of {PublicKey} from an octet string.
    #
    # @param octet_string [String]
    # @param hasher [Hasher]
    # @return [PublicKey]
    def self.from_octet(octet_string, hasher)
      point = ECDSA::Format::PointOctetString.decode(octet_string, hasher.group)
      PublicKey.new(point, hasher)
    end

    # Encodes this public key into an octet string. The encoded data contains
    # only the point. It does not contain the hasher.
    #
    # @param opts [Hash]
    # @option opts [Boolean] :compression (true)
    # @return [String]
    def to_hex(opts = {})
      compression = opts.delete(:compression) { true }
      raise ArgumentError, "Unknown opts: #{opts.keys.join(', ')}" unless opts.empty?

      to_octet(compression: compression).unpack('H*').first
    end

    # Encodes this public key into a hex string. The encoded data contains
    # only the point. It does not contain the hasher.
    #
    # @param opts [Hash]
    # @option opts [Boolean] :compression (true)
    # @return [String]
    def to_octet(opts = {})
      compression = opts.delete(:compression) { true }
      raise ArgumentError, "Unknown opts: #{opts.keys.join(', ')}" unless opts.empty?

      ECDSA::Format::PointOctetString.encode(point, compression: compression)
    end

    # @return [PublicKey] self.
    def public_key
      self
    end

    # @return [Boolean] true if the public keys are equal.
    def ==(other)
      return false unless other.is_a?(PublicKey)
      point == other.point && hasher == other.hasher
    end
  end
end
