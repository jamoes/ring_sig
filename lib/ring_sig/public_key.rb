module RingSig
  # Instances of this class represent a public ECDSA key.
  class PublicKey

    # The elliptical curve point of this public key.
    #
    # @return [ECDSA::Point]
    attr_reader :point

    # @return [ECDSA::Group]
    attr_reader :group

    # Creates a new instance of {PublicKey}.
    #
    # @param point [ECDSA::Point]
    # @param group [ECDSA::Group]
    def initialize(point, group: ECDSA::Group::Secp256k1)
      raise ArgumentError, "Point is not an ECDSA::Point" unless point.is_a?(ECDSA::Point)
      raise ArgumentError, "Point is not on the group's curve" unless group.include?(point)

      @point = point
      @group = group
    end

    # Creates a new instance of {PublicKey} from a hex string.
    #
    # @param hex_string [String]
    # @param group [ECDSA::Group]
    # @return [PublicKey]
    def self.from_hex(hex_string, group: ECDSA::Group::Secp256k1)
      self.from_octet([hex_string].pack('H*'), group: group)
    end

    # Creates a new instance of {PublicKey} from an octet string.
    #
    # @param octet_string [String]
    # @param group [ECDSA::Group]
    # @return [PublicKey]
    def self.from_octet(octet_string, group: ECDSA::Group::Secp256k1)
      point = ECDSA::Format::PointOctetString.decode(octet_string, group)
      PublicKey.new(point, group: group)
    end

    # Encodes this public key into an octet string. The encoded data contains
    # only the point. It does not contain the group.
    #
    # @param compression [Boolean]
    # @return [String]
    def to_hex(compression: true)
      to_octet(compression: compression).unpack('H*').first
    end

    # Encodes this public key into a hex string. The encoded data contains
    # only the point. It does not contain the group.
    #
    # @param compression [Boolean]
    # @return [String]
    def to_octet(compression: true)
      ECDSA::Format::PointOctetString.encode(point, compression: compression)
    end

    # @return [PublicKey] self.
    def public_key
      self
    end

    # @return [Boolean] true if the public keys are equal.
    def ==(other)
      return false unless other.is_a?(PublicKey)
      point == other.point && group == other.group
    end
  end
end
