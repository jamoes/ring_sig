require File.expand_path('../lib/ring_sig/version', __FILE__)

Gem::Specification.new do |s|
  s.name        = 'ring_sig'
  s.version     = RingSig::VERSION
  s.authors     = ['Stephen McCarthy']
  s.email       = 'sjmccarthy@gmail.com'
  s.summary     = 'This gem implements ring signatures, built on top of ECDSA, as specified by CryptoNote'
  s.description = 'Ring Signatures allow someone to non-interactively sign a message which can be verified against a set of chosen public keys.'
  s.homepage    = 'https://github.com/jamoes/ring_sig'
  s.license     = 'MIT'

  s.files       = `git ls-files`.split("\n")
  s.executables = s.files.grep(%r{^bin/}).map{ |f| File.basename(f) }
  s.test_files  = s.files.grep(%r{^(test|spec|features)/})

  s.add_development_dependency 'bundler', '~> 1.3'
  s.add_development_dependency 'rake', '~> 10'
  s.add_development_dependency 'rspec', '~> 3.0'
  s.add_development_dependency 'simplecov', '~> 0'
  s.add_development_dependency 'yard', '~> 0'
  s.add_development_dependency 'markdown', '~> 1'
  s.add_development_dependency 'redcarpet', '~> 3' unless RUBY_PLATFORM == 'java'

  s.add_runtime_dependency 'ecdsa', '~> 1.2'
end
