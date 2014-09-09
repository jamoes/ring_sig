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

  context 'Simple hasher, simple group' do
    let(:group) do
      # A simple group with order equal to 200
      ECDSA::Group.new(name: 'simple', p: 1, a: 1, b: 1, g: [0, 1], n: 200, h: 1)
    end

    let(:hash_algorithm) do
      # A hash algorithm which returns a number less than 256
      stub_const 'SimpleHashAlgorithm', Class.new
      SimpleHashAlgorithm.class_eval do
        def self.digest(s)
          [(OpenSSL::Digest::SHA256.hexdigest(s).to_i(16) % 256).to_s(16)].pack('H*')
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
    it_behaves_like 'hash algorithm', "\xE9", "\xD0" # 208
    it_behaves_like 'hash algorithm', "\xD0", "\x15" # 21

    describe '#hash_string' do
      it 'hashes "a" to 187' do
        expect(hasher.hash_string('a')).to eq 187
      end

      it 'hashes "0" to 21' do
        expect(hasher.hash_string('0')).to eq 21
      end
    end
  end
end
