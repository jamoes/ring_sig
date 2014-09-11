require 'spec_helper'

describe RingSig::PublicKey do
  compressed_hex = '03678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb6'
  uncompressed_hex = '04678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb649f6bc3f4cef38c4f35504e51ec112de5c384df7ba0b8d578a4c702b6bf11d5f'
  group = ECDSA::Group::Secp256k1
  key = RingSig::PublicKey.new(group.new_point([
    46833799212576611471711417854818141128240043280360231002189938627535641370294,
    33454781559405909841731692443380420218121109572881027288991311028992835919199
    ]))

  describe '#to_hex' do
    it 'converts to compressed hex' do
      expect(key.to_hex(compression: true)).to eq compressed_hex
    end

    it 'converts to uncompressed hex' do
      expect(key.to_hex(compression: false)).to eq uncompressed_hex
    end
  end

  describe '#from_hex' do
    it 'converts from compressed hex' do
      expect(RingSig::PublicKey.from_hex(compressed_hex)).to eq key
    end

    it 'converts from uncompressed hex' do
      expect(RingSig::PublicKey.from_hex(uncompressed_hex)).to eq key
    end
  end

  describe '#to_octet' do
    it 'converts to compressed octet' do
      expect(key.to_octet(compression: true)).to eq [compressed_hex].pack('H*')
    end

    it 'converts to uncompressed octet' do
      expect(key.to_octet(compression: false)).to eq [uncompressed_hex].pack('H*')
    end
  end

  describe '#from_octet' do
    it 'converts from compressed octet' do
      expect(RingSig::PublicKey.from_octet([compressed_hex].pack('H*'))).to eq key
    end

    it 'converts from uncompressed octet' do
      expect(RingSig::PublicKey.from_octet([uncompressed_hex].pack('H*'))).to eq key
    end
  end

  describe '==' do
    it 'returns true when keys are the same' do
      expect(key).to eq key
      expect(RingSig::PublicKey.new(key.point) == key).to eq true
    end

    it 'returns false when keys are different' do
      expect(RingSig::PublicKey.new(group.generator) == key).to eq false
    end
  end
end
