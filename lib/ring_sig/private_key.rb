module RingSig
  # Instances of this class represent a private ECDSA key.
  class PrivateKey

    # The integer value of this private key. A number between 0 and the
    # group's order (non-inclusive).
    #
    # @return [Integer]
    attr_reader :value

    # @return [PublicKey]
    attr_reader :public_key

    # @return [Hasher]
    attr_reader :hasher

    # Creates a new instance of {PrivateKey}.
    #
    # @param value [Integer]
    # @param hasher [Hasher]
    def initialize(value, hasher)
      raise ArgumentError, "Value is not an integer" unless value.is_a?(Integer)
      raise ArgumentError, "Value is too small" if value < 1
      raise ArgumentError, "Value is too large" if value >= hasher.group.order

      @value = value
      @hasher = hasher
      @public_key = PublicKey.new(hasher.group.generator * value, hasher)
    end

    # Creates a new instance of {PrivateKey} from a hex string.
    #
    # @param hex_string [String]
    # @param hasher [Hasher]
    # @return [PrivateKey]
    def self.from_hex(hex_string, hasher)
      self.from_octet([hex_string].pack('H*'), hasher)
    end

    # Creates a new instance of {PrivateKey} from an octet string.
    #
    # @param octet_string [String]
    # @param hasher [Hasher]
    # @return [PrivateKey]
    def self.from_octet(octet_string, hasher)
      value = ECDSA::Format::FieldElementOctetString.decode(octet_string, hasher.group.field)
      PrivateKey.new(value, hasher)
    end

    # Encodes this private key into an octet string. The encoded data contains
    # only the value. It does not contain the hasher.
    #
    # @return [String]
    def to_hex
      to_octet.unpack('H*').first
    end

    # Encodes this public key into a hex string. The encoded data contains
    # only the value. It does not contain the hasher.
    #
    # @return [String]
    def to_octet
      ECDSA::Format::FieldElementOctetString.encode(value, hasher.group.field)
    end

    # Signs a message with this key's private key and a set of foreign public
    # keys. The resulting signature can be verified against the ordered set of
    # all public keys used for creating this signature. The signature will also
    # contain a key_image which will be the same for all messages signed with
    # this key.
    #
    # @param message [String] The message to sign.
    # @param foreign_keys [Array<PublicKey>] The foreign keys for the signature.
    # @return [Array(Signature, Array<PublicKey>)] A pair containing the signature
    #   and the set of public keys (in the correct order) for verifying.
    def sign(message, foreign_keys)
      raise ArgumentError "Foreign keys must all have the same hasher" unless foreign_keys.all?{ |e| e.hasher == hasher }

      message_digest = hasher.hash_string(message)
      seed = hasher.hash_array([value, message_digest])

      all_keys = hasher.shuffle([self] + foreign_keys, seed)

      q_array, w_array = generate_q_w(all_keys, seed)
      ll_array, rr_array = generate_ll_rr(all_keys, q_array, w_array)
      challenge = hasher.hash_array([message_digest] + ll_array + rr_array)
      c_array, r_array = generate_c_r(all_keys, q_array, w_array, challenge)

      public_keys = all_keys.map(&:public_key)
      signature = Signature.new(key_image, c_array, r_array, hasher)

      [signature, public_keys]
    end

    # @return [ECDSA::Point] the key image.
    def key_image
      @key_image ||= hasher.hash_point(point) * value
    end

    # @return [ECDSA::Point] the public key's point.
    def point
      public_key.point
    end

    # @return [Boolean] true if the private keys are equal.
    def ==(other)
      return false unless other.is_a?(PrivateKey)
      value == other.value && hasher == other.hasher
    end

    private

    def generate_q_w(all_keys, seed)
      q_array, w_array = [], []

      all_keys.each_with_index do |k, i|
        q_array[i] = hasher.hash_array(['q', seed, i])
        w_array[i] = 0
        w_array[i] = hasher.hash_array(['w', seed, i]) if k.is_a?(PublicKey)
      end

      [q_array, w_array]
    end

    def generate_ll_rr(all_keys, q_array, w_array)
      ll_array, rr_array = [], []

      all_keys.each_with_index do |k, i|
        ll_array[i] = hasher.group.generator * q_array[i]
        rr_array[i] = hasher.hash_point(k.point) * q_array[i]
        if k.is_a?(PublicKey)
          ll_array[i] += k.point * w_array[i]
          rr_array[i] += key_image * w_array[i]
        end
      end

      [ll_array, rr_array]
    end

    def generate_c_r(all_keys, q_array, w_array, challenge)
      c_array, r_array = [], []

      all_keys.each_with_index do |k, i|
        if k.is_a?(PublicKey)
          c_array[i] = w_array[i]
          r_array[i] = q_array[i]
        else
          c_array[i] = (challenge - w_array.inject{|a, b| a + b}) % hasher.group.order
          r_array[i] = (q_array[i] - c_array[i] * k.value) % hasher.group.order
        end
      end

      [c_array, r_array]
    end
  end
end
