# coding: utf-8
lib = File.expand_path('../lib', __FILE__)
$LOAD_PATH.unshift(lib) unless $LOAD_PATH.include?(lib)
require 'rasl/version'

Gem::Specification.new do |spec|
  spec.name         = 'rasl'
  spec.version      = Rasl::VERSION
  spec.author       = 'akicho8'
  spec.email        = 'akicho8@gmail.com'
  spec.homepage     = 'https://github.com/akicho8/rasl'
  spec.summary      = 'CASL Assembler / Simulator'
  spec.description  = 'CASL Assembler / Simulator'
  spec.platform     = Gem::Platform::RUBY

  spec.files         = `git ls-files`.split($/)
  spec.executables   = spec.files.grep(%r{^bin/}) { |f| File.basename(f) }
  spec.test_files    = spec.files.grep(%r{^(test|spec|features)/})
  spec.require_paths = ['lib']
  spec.rdoc_options  = ['--line-numbers', '--inline-source', '--charset=UTF-8', '--diagram', '--image-format=jpg']

  spec.add_dependency 'activesupport'
  spec.add_dependency 'activemodel'

  spec.add_development_dependency 'bundler', '~> 1.3'
  spec.add_development_dependency 'rake'
  spec.add_development_dependency 'rspec'
  spec.add_development_dependency 'byebug'
end
