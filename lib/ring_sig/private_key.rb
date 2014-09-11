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

    # @return [ECDSA::Group]
    attr_reader :group

    # @return [#digest]
    attr_reader :hash_algorithm

    # Creates a new instance of {PrivateKey}.
    #
    # @param value [Integer]
    # @param group [ECDSA::Group]
    # @param hash_algorithm [#digest]
    def initialize(value, group: ECDSA::Group::Secp256k1, hash_algorithm: OpenSSL::Digest::SHA256)
      raise ArgumentError, "Value is not an integer" unless value.is_a?(Integer)
      raise ArgumentError, "Value is too small" if value < 1
      raise ArgumentError, "Value is too large" if value >= group.order

      @value = value
      @public_key = PublicKey.new(group.generator.multiply_by_scalar(value), group: group)

      @group = group
      @hash_algorithm = hash_algorithm
      @hasher = Hasher.new(group, hash_algorithm)
    end

    # Creates a new instance of {PrivateKey} from a hex string.
    #
    # @param octet_string [String]
    # @param group [ECDSA::Group]
    # @param hash_algorithm [#digest]
    # @return [PrivateKey]
    def self.from_hex(hex_string, group: ECDSA::Group::Secp256k1, hash_algorithm: OpenSSL::Digest::SHA256)
      self.from_octet([hex_string].pack('H*'), group: group, hash_algorithm: hash_algorithm)
    end

    # Creates a new instance of {PrivateKey} from an octet string.
    #
    # @param octet_string [String]
    # @param group [ECDSA::Group]
    # @param hash_algorithm [#digest]
    # @return [PrivateKey]
    def self.from_octet(octet_string, group: ECDSA::Group::Secp256k1, hash_algorithm: OpenSSL::Digest::SHA256)
      value = ECDSA::Format::FieldElementOctetString.decode(octet_string, group.field)
      PrivateKey.new(value, group: group, hash_algorithm: hash_algorithm)
    end

    # Encodes this private key into an octet string. The encoded data contains
    # only the value. It does not contain the group or hash_algorithm.
    #
    # @return [String]
    def to_hex
      to_octet.unpack('H*').first
    end

    # Encodes this public key into a hex string. The encoded data contains
    # only the value. It does not contain the group or hash_algorithm.
    #
    # @return [String]
    def to_octet
      ECDSA::Format::FieldElementOctetString.encode(value, group.field)
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
      raise ArgumentError "Foreign keys must all have the same group" unless foreign_keys.all?{ |e| e.group == group }

      message_digest = @hasher.hash_string(message)
      seed = @hasher.hash_array([value, message_digest])

      all_keys = @hasher.shuffle([self] + foreign_keys, seed)

      q_array, w_array = generate_q_w(all_keys, seed)
      ll_array, rr_array = generate_ll_rr(all_keys, q_array, w_array)
      challenge = @hasher.hash_array([message_digest] + ll_array + rr_array)
      c_array, r_array = generate_c_r(all_keys, q_array, w_array, challenge)

      public_keys = all_keys.map(&:public_key)
      signature = Signature.new(key_image, c_array, r_array, group: group, hash_algorithm: @hasher.algorithm)

      [signature, public_keys]
    end

    # @return [ECDSA::Point] the key image.
    def key_image
      @key_image ||= @hasher.hash_point(point) * value
    end

    # @return [ECDSA::Point] the public key's point.
    def point
      public_key.point
    end

    # @return [Boolean] true if the private keys are equal.
    def ==(other)
      return false unless other.is_a?(PrivateKey)
      value == other.value && group == other.group && hash_algorithm == other.hash_algorithm
    end

    private

    def generate_q_w(all_keys, seed)
      q_array, w_array = [], []

      all_keys.each_with_index do |k, i|
        q_array[i] = @hasher.hash_array(['q', seed, i])
        w_array[i] = 0
        w_array[i] = @hasher.hash_array(['w', seed, i]) if k.is_a?(PublicKey)
      end

      [q_array, w_array]
    end

    def generate_ll_rr(all_keys, q_array, w_array)
      ll_array, rr_array = [], []

      all_keys.each_with_index do |k, i|
        ll_array[i] = group.generator * q_array[i]
        rr_array[i] = @hasher.hash_point(k.point) * q_array[i]
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
          c_array[i] = (challenge - w_array.inject{|a, b| a + b}) % group.order
          r_array[i] = (q_array[i] - c_array[i] * k.value) % group.order
        end
      end

      [c_array, r_array]
    end
  end
end
