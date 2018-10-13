$LOAD_PATH.unshift File.expand_path('..', __FILE__)
$LOAD_PATH.unshift File.expand_path('../../lib', __FILE__)

require 'dotenv'
require 'sinatra'
require 'omniauth'
require 'omniauth-patreon'

Dotenv.load

enable :sessions

use OmniAuth::Builder do
  provider :patreon, ENV['CLIENT_ID'], ENV['CLIENT_SECRET'] # , :scope => 'profile'
end

get '/' do
  <<-HTML
  <a href='/auth/patreon'>Sign in with patreon</a>
  HTML
end

get '/auth/failure' do
  env['omniauth.error'].to_s
end

get '/auth/:name/callback' do
  auth = request.env['omniauth.auth']

  puts %(
    >> UID
      #{auth.uid.inspect}

    >> CREDENTIALS
      #{auth.credentials.inspect}

    >> INFO
      #{auth.info.inspect}
      #
    >> EXTRA
      #{auth.extra.inspect}
  )

  'Check logs for user information.'
end
