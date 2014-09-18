require 'spec_helper'

describe RingSig::Hasher do
  context 'Standard: SHA256 hash algorithm, secp256k1 group' do
    group = ECDSA::Group::Secp256k1
    hash_algorithm = OpenSSL::Digest::SHA256
    hasher = RingSig::Hasher.new(group, hash_algorithm)

    describe '#hash_string' do
      it 'hashes "a"' do
        expect(hasher.hash_string('a')).to eq 91634880152443617534842621287039938041581081254914058002978601050179556493499
      end
    end

    describe '#hash_array' do
      it 'hashes array of integers' do
        expect(hasher.hash_array([1, 2, 3])).to eq 108327230196833505301150634709321652091196191739965401474258808571764922687322
      end

      it 'hashes array of strings' do
        expect(hasher.hash_array(%w(a b c))).to eq 9077136522292755305325573261332124424180056729600426071187952904380324423800
      end

      it 'hashes array of points' do
        expect(hasher.hash_array([group.generator, group.generator])).to eq 112151076631064605889327921696882492390839695314815668972759101076317607858646
      end

      it 'hashes mixes array' do
        expect(hasher.hash_array([1, 'a', group.generator])).to eq 43575008266016611275304127474943853239256831409985077531779052441823152705495
      end

      it 'raises ArgumentError on invalid types' do
        expect { hasher.hash_array([1.1]) }.to raise_error(ArgumentError)
        expect { hasher.hash_array([[]]) }.to raise_error(ArgumentError)
        expect { hasher.hash_array([{}]) }.to raise_error(ArgumentError)
      end
    end

    describe '#hash_point' do
      it 'hashes generator point' do
        expected_point = group.new_point([0x2bcb1a5b3c70421bfac818f6bd13289a5c9a3cfb42d3b81f023a0276974c9245, 0xe465a0409b09a11894755e9b9d6e86938d1b5035587458ad29c00154ddfc9de])
        expect(hasher.hash_point(group.generator)).to eq expected_point
      end
    end

    describe '#shuffle' do
      it 'shuffles deterministically' do
        expect(hasher.shuffle([1, 2, 3, 4, 5, 6], 1)).to eq [6, 3, 4, 1, 5, 2]
      end
    end
  end

  context 'Simple hash algorithm, simple group' do
    let(:group) do
      # A simple 8-bit group with order equal to 200
      ECDSA::Group.new(name: 'simple', p: 211, a: 1, b: 1, g: [0, 1], n: 200, h: 1)
    end

    let(:hash_algorithm) do
      # A hash algorithm which returns a number less than 256
      stub_const 'SimpleHashAlgorithm', Class.new
      SimpleHashAlgorithm.class_eval do
        def self.digest(s)
          [OpenSSL::Digest::SHA256.hexdigest(s)[-2,2]].pack('H*')
        end
      end
      SimpleHashAlgorithm
    end

    let(:hasher) { RingSig::Hasher.new(group, hash_algorithm) }

    # We test the hash_algorithm itself in this context, since we implemented our own simple hash_algorithm.
    shared_examples_for 'hash algorithm' do |input, expected_value|
      it 'Hashes input to expected_value' do
        expect(hash_algorithm.digest(input)).to eq expected_value.force_encoding('binary')
      end
    end
    it_behaves_like 'hash algorithm', 'a',    "\xBB" # 187
    it_behaves_like 'hash algorithm', '0',    "\xE9" # 233
    it_behaves_like 'hash algorithm', "\xE9", "\r"   # 13

    describe '#hash_string' do
      it 'hashes "a" to 187' do
        expect(hasher.hash_string('a')).to eq 187
      end

      it 'hashes "0" to 13' do
        expect(hasher.hash_string('0')).to eq 13
      end
    end
  end

  context 'Curve25519-like group' do
    # This gem is not yet compatible with Curve25519, but we still test the
    # hasher against it. Curve25519 has a distinct characteristic: its
    # order is much smaller than its prime.
    let(:group) do
      ECDSA::Group.new(name: 'Curve25519-like', p: 2**255-19, a: 1, b: 1, g: [0, 1], n: 2**252+27742317777372353535851937790883648493, h: 1)
    end

    let(:hasher) { RingSig::Hasher.new(group, OpenSSL::Digest::SHA256) }

    describe '#hash_string' do
      it 'hashes "a"' do
        expect(hasher.hash_string('a')).to eq 4790813224456470967164382530524007151295684942355166730955189790754105481631
      end

      it 'hashes "0"' do
        expect(hasher.hash_string('0')).to eq 7203293323279838689554303289673273753938185156274697627287051646710131340360
      end
    end

  end

  context 'Non-matching byte-lengths' do
    it 'raises an ArgumentError if group byte length does not match the hash algorithm byte length' do
      expect { RingSig::Hasher.new(ECDSA::Group::Secp256k1, OpenSSL::Digest::SHA224) }.to raise_error(ArgumentError)
    end
  end

  context 'ECDSA group with an order larger than the maximum digest size' do
    it 'raises an ArgumentError' do
      expect { RingSig::Hasher.new(ECDSA::Group::Secp160k1, OpenSSL::Digest::RIPEMD160) }.to raise_error(ArgumentError)
    end
  end

end
