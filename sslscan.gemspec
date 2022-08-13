# coding: utf-8
lib = File.expand_path('../lib', __FILE__)
$LOAD_PATH.unshift(lib) unless $LOAD_PATH.include?(lib)
require 'ssl_scan/version'

Gem::Specification.new do |spec|
  spec.name          = "ssl_scan"
  spec.version       = SSLScan::VERSION::STRING
  spec.authors       = ["John Faucett"]
  spec.email         = ["jwaterfaucett@gmail.com"]
  spec.summary       = %q{Ruby SSL Scanner}
  spec.description   = %q{An SSL Scanner Library and Utility in pure Ruby}
  spec.homepage      = "https://github.com/jwaterfaucett/ssl_scan"
  spec.license       = "MIT"

  spec.files         = `git ls-files -z`.split("\x0")
  spec.executables   = spec.files.grep(%r{^bin/}) { |f| File.basename(f) }
  spec.test_files    = spec.files.grep(%r{^(test|spec|features)/})
  spec.require_paths = ["lib"]

  spec.add_runtime_dependency "fast_gettext", "~> 0.8"

  spec.add_development_dependency "bundler"
  spec.add_development_dependency "rake"
  spec.add_development_dependency "rspec", "~> 3.0"
  spec.add_development_dependency "gettext"
end
