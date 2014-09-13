module RingSig
  # A customized hasher specifically for Ring Signatures.
  class Hasher
    # @return [ECDSA::Group]
    attr_reader :group

    # @return [#digest]
    attr_reader :hash_algorithm

    # Creates a new instance of {Hasher}.
    #
    # @param opts [Hash]
    # @option opts :group [ECDSA::Group]
    # @option opts :hash_algorithm [#digest]
    def initialize(opts = {})
      @group = opts.delete(:group) { RingSig.default_group }
      @hash_algorithm = opts.delete(:hash_algorithm) { RingSig.default_hash_algorithm }
      raise ArgumentError, "Unknown options #{opts.keys.join(', ')}" unless opts.empty?
    end

    # Continuously hashes until a value less than the group's order is found.
    #
    # @param s (String) The value to be hashed.
    # @return (Integer) A number between 0 and the group's order.
    def hash_string(s)
      n = nil
      loop do
        s = @hash_algorithm.digest(s)
        n = s.unpack('H*').first.to_i(16)
        break if n < @group.order
      end
      n
    end

    # Hashes an array. Converts the Array to an OpenSSL::ASN1::Sequence der
    # string, and then hashes that string.
    #
    # @param array [Array<String,Integer,ECDSA::Point>] The array to be hashed.
    # @return [Integer] A number between 0 and the group's order.
    def hash_array(array)
      array = array.map do |e|
        case e
        when String
          OpenSSL::ASN1::UTF8String.new(e)
        when Integer
          OpenSSL::ASN1::Integer.new(e)
        when ECDSA::Point
          OpenSSL::ASN1::OctetString.new(ECDSA::Format::PointOctetString.encode(e, compression: true))
        else
          raise ArgumentError, "Unsupported type: #{p.inspect}"
        end
      end

      hash_string(OpenSSL::ASN1::Sequence.new(array).to_der)
    end

    # Hashes a point to another point.
    #
    # @param point [ECDSA::Point] The point to be hashed.
    # @return [ECDSA::Point] A new point, deterministically computed from the input point.
    def hash_point(point)
      @group.generator * hash_array(point.coords)
    end

    # Shuffles an array in a deterministic manner.
    #
    # @param array (Array) The array to be shuffled.
    # @param seed (Integer) A random seed which determines the outcome of the suffle.
    # @return (Array) The shuffled array.
    def shuffle(array, seed)
      seed_array = [seed, 0]
      (array.size - 1).downto(1) do |i|
        r = next_rand(i + 1, seed_array)
        array[i], array[r] = array[r], array[i]
      end
      array
    end

    private

    # Deterministically returns a random number between 0 and n.
    #
    # @param n (Integer) The maximum value.
    # @param seed_array (Array<Integer>) A pair `[seed, suffix]`.
    #   The suffix will be modified.
    # @return (Integer) A number between 0 and n.
    def next_rand(n, seed_array)
      loop do
        r = hash_array(seed_array)
        seed_array[1] += 1
        return r % n if r < @group.order - @group.order % n
      end
    end
  end
end
