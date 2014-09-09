module RingSig
  # Instances of this class represent an ECDSA key.
  class Key

    # @return [Integer]
    attr_reader :private_key

    # @return [ECDSA::Point]
    attr_reader :public_key

    # @return [ECDSA::Group]
    attr_reader :group

    # @return [#digest]
    attr_reader :hash_algorithm

    # Creates a new instance of {Key}. Must provide  either a private_key or
    # a public_key, but not both.
    #
    # @param private_key [Integer]
    # @param public_key [ECDSA::Point]
    # @param group [ECDSA::Group]
    # @param hash_algorithm [#digest]
    def initialize(
       private_key:    nil,
       public_key:     nil,
       group:          ECDSA::Group::Secp256k1,
       hash_algorithm: OpenSSL::Digest::SHA256)

      if private_key && public_key
        raise ArgumentError, "Must not provide both private_key and public_key"
      elsif private_key
        raise ArgumentError, "Private key is not an integer" unless private_key.is_a?(Integer)
        raise ArgumentError, "Private key is too small" if private_key < 1
        raise ArgumentError, "Private key is too large" if private_key >= group.order
        @private_key = private_key
        @public_key = group.generator.multiply_by_scalar(private_key)
      elsif public_key
        raise ArgumentError, "Public key is not an ECDSA::Point" unless public_key.is_a?(ECDSA::Point)
        raise ArgumentError, "Public key is not on the group's curve" unless group.include?(public_key)
        @public_key = public_key
      else
        raise ArgumentError, "Must provide either private_key or public_key"
      end

      @group = group
      @hash_algorithm = hash_algorithm
      @hasher = RingSig::Hasher.new(group, hash_algorithm)
    end

    # Signs a message with this key's private_key and a set of public foreign
    # keys. The resulting signature can be verified against the ordered set of
    # all public keys used for creating this signature. The signature will also
    # contain a key_image which will be the same for all messages signed with
    # this key.
    #
    # @param message [String] The message to sign.
    # @param foreign_keys [Array<Key>] The foreign keys for the signature.
    # @return [Array(Signature, Array<Key>)] A pair containing the signature
    #   and the set of public keys (in the correct order) for verifying.
    def sign(message, foreign_keys)
      raise ArgumentError "Cannot sign without a private key" unless private_key
      raise ArgumentError "Foreign keys must all have to the same group" unless foreign_keys.all?{|e| e.group == group}
      raise ArgumentError "Foreign keys must all have to the same hash_algorithm" unless foreign_keys.all?{|e| e.hash_algorithm == hash_algorithm}

      message_digest = @hasher.hash_string(message)
      seed = @hasher.hash_array([private_key, message_digest])

      foreign_keys = foreign_keys.map(&:drop_private_key)
      all_keys = @hasher.shuffle([self] + foreign_keys, seed)

      q_array, w_array = generate_q_w(all_keys, seed)
      ll_array, rr_array = generate_ll_rr(all_keys, q_array, w_array)
      challenge = @hasher.hash_array([message_digest] + ll_array + rr_array)
      c_array, r_array = generate_c_r(all_keys, q_array, w_array, challenge)

      public_keys = all_keys.map(&:drop_private_key)

      [RingSig::Signature.new(key_image, c_array, r_array, group: group, hash_algorithm: @hasher.algorithm), public_keys]
    end

    # @return [ECDSA::Point] the key image.
    def key_image
      raise ArgumentError "Cannot compute key image without the private key" unless private_key
      @key_image ||= @hasher.hash_point(@public_key) * @private_key
    end

    # Returns self if this key has no private key. Otherwise, returns a new key
    # with only the public_key component.
    #
    # @return [Key]
    def drop_private_key
      return self unless private_key
      Key.new(public_key: public_key, group: group, hash_algorithm: hash_algorithm)
    end

    private

    def generate_q_w(all_keys, seed)
      q_array, w_array = [], []

      all_keys.each_with_index do |k, i|
        q_array[i] = @hasher.hash_array(['q', seed, i])
        w_array[i] = @hasher.hash_array(['w', seed, i])
        w_array[i] = 0 if k.private_key
      end

      [q_array, w_array]
    end

    def generate_ll_rr(all_keys, q_array, w_array)
      ll_array, rr_array = [], []

      all_keys.each_with_index do |k, i|
        ll_array[i] = group.generator * q_array[i]
        rr_array[i] = @hasher.hash_point(k.public_key) * q_array[i]
        if k.private_key.nil?
          ll_array[i] += k.public_key * w_array[i]
          rr_array[i] += key_image * w_array[i]
        end
      end

      [ll_array, rr_array]
    end

    def generate_c_r(all_keys, q_array, w_array, challenge)
      c_array, r_array = [], []

      all_keys.each_with_index do |k, i|
        if k.private_key.nil?
          c_array[i] = w_array[i]
          r_array[i] = q_array[i]
        else
          c_array[i] = (challenge - w_array.inject{|a, b| a + b}) % group.order
          r_array[i] = (q_array[i] - c_array[i] * k.private_key) % group.order
        end
      end

      [c_array, r_array]
    end
  end
end
