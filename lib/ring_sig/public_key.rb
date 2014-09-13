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
    # @param opts [Hash]
    # @option opts :group [ECDSA::Group]
    def initialize(point, opts = {})
      @group = opts.delete(:group) { RingSig.default_group }
      raise ArgumentError, "Unknown opts: #{opts.keys.join(', ')}" unless opts.empty?

      raise ArgumentError, "Point is not an ECDSA::Point" unless point.is_a?(ECDSA::Point)
      raise ArgumentError, "Point is not on the group's curve" unless group.include?(point)

      @point = point
    end

    # Creates a new instance of {PublicKey} from a hex string.
    #
    # @param hex_string [String]
    # @param opts [Hash]
    # @option opts :group [ECDSA::Group]
    # @return [PublicKey]
    def self.from_hex(hex_string, opts = {})
      group = opts.delete(:group) { RingSig.default_group }
      raise ArgumentError, "Unknown opts: #{opts.keys.join(', ')}" unless opts.empty?

      self.from_octet([hex_string].pack('H*'), group: group)
    end

    # Creates a new instance of {PublicKey} from an octet string.
    #
    # @param octet_string [String]
    # @param opts [Hash]
    # @option opts :group [ECDSA::Group]
    # @return [PublicKey]
    def self.from_octet(octet_string, opts = {})
      group = opts.delete(:group) { RingSig.default_group }
      raise ArgumentError, "Unknown opts: #{opts.keys.join(', ')}" unless opts.empty?

      point = ECDSA::Format::PointOctetString.decode(octet_string, group)
      PublicKey.new(point, group: group)
    end

    # Encodes this public key into an octet string. The encoded data contains
    # only the point. It does not contain the group.
    #
    # @param opts [Hash]
    # @option opts :compression [Boolean]
    # @return [String]
    def to_hex(opts = {})
      compression = opts.delete(:compression) { true }
      raise ArgumentError, "Unknown opts: #{opts.keys.join(', ')}" unless opts.empty?

      to_octet(compression: compression).unpack('H*').first
    end

    # Encodes this public key into a hex string. The encoded data contains
    # only the point. It does not contain the group.
    #
    # @param opts [Hash]
    # @option opts :compression [Boolean]
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
      point == other.point && group == other.group
    end
  end
end
