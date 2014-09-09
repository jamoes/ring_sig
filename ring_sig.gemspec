require File.expand_path('../lib/ring_sig/version', __FILE__)

Gem::Specification.new do |s|
  s.name        = 'ring_sig'
  s.version     = RingSig::VERSION
  s.authors     = ['Stephen McCarthy']
  s.email       = 'sjmccarthy@gmail.com'
  s.summary     = 'This gem implements ring signatures, built on top of ECDSA, as specified by CryptoNote'
  s.homepage    = 'https://github.com/jamoes/ring_sig'
  s.license     = 'MIT'

  s.files       = `git ls-files`.split("\n")
  s.executables = s.files.grep(%r{^bin/}).map{ |f| File.basename(f) }
  s.test_files  = s.files.grep(%r{^(test|spec|features)/})

  s.add_development_dependency 'bundler', '~> 1.3'
  s.add_development_dependency 'rake'
  s.add_development_dependency 'rspec', '~> 3.0'
  s.add_development_dependency 'simplecov'
  s.add_development_dependency 'yard'
  s.add_development_dependency 'markdown'
  s.add_development_dependency 'redcarpet'

  s.add_runtime_dependency 'ecdsa', '~> 1.1'
end
