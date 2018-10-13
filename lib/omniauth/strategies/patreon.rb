require 'omniauth-oauth2'

module OmniAuth
  module Strategies
    class Patreon < OmniAuth::Strategies::OAuth2
      DEFAULT_SCOPE = 'users pledges-to-me my-campaign'.freeze

      option :client_options, site: 'https://www.patreon.com/api/oauth2/api',
                              authorize_url: 'https://patreon.com/oauth2/authorize',
                              token_url: 'https://patreon.com/api/oauth2/token'

      uid { raw_info['uuid'] }

      info do
        {
          first_name: raw_info['first_name'],
          last_name: raw_info['last_name'],
          email: raw_info['email'],
          picture: raw_info['picture'],
          promo_code: raw_info['promo_code']
        }
      end

      extra do
        {
          raw_info: raw_info
        }
      end

      def raw_info
        @raw_info ||= access_token.get('/current_user').parsed || {}
      end

      def request_phase
        options[:authorize_params] = {
          client_id: options['client_id'],
          response_type: 'code',
          scopes: (options['scope'] || DEFAULT_SCOPE)
        }

        super
      end
    end
  end
end
