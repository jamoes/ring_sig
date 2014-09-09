if ENV['COVERAGE'] == 'Y'
  require 'simplecov'
  SimpleCov.start
end

require 'ring_sig'
