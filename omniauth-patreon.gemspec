# -*- encoding: utf-8 -*-

$LOAD_PATH.push File.expand_path('../lib', __FILE__)
require 'omniauth/patreon/version'

Gem::Specification.new do |s|
  s.name          = 'omniauth-patreon'
  s.version       = OmniAuth::Patreon::VERSION
  s.authors       = ['Kristian Freeman']
  s.email         = ['kristian@bytesized.xyz']
  s.summary       = 'Patreon strategy for OmniAuth'
  s.description   = 'Patreon strategy for OmniAuth v1.2'
  s.homepage      = 'https://github.com/tmilewski/omniauth-patreon'
  s.license       = 'MIT'

  s.files         = `git ls-files`.split("\n")
  s.test_files    = `git ls-files -- {test,spec,features}/*`.split("\n")
  s.executables   = `git ls-files -- bin/*`.split("\n").collect { |f| File.basename(f) }
  s.require_paths = ['lib']

  s.add_runtime_dependency 'omniauth', '~> 1.2'
  s.add_runtime_dependency 'omniauth-oauth2', '~> 1.1'

  s.add_development_dependency 'dotenv', '>= 2.0'
  s.add_development_dependency 'sinatra', '>= 2.0'
end
