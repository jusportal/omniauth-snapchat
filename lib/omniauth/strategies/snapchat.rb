require 'omniauth/strategies/oauth2'
require 'multi_json'

module OmniAuth
  module Strategies
    class Snapchat < OmniAuth::Strategies::OAuth2

      option :name, "snapchat"

      option :client_options, {
        site: 'https://adsapi.snapchat.com',
        authorize_url: 'https://accounts.snapchat.com/login/oauth2/authorize',
        token_url: 'https://accounts.snapchat.com/login/oauth2/access_token',
        auth_scheme: :request_body
      }

      credentials do
        hash = {}
        hash['token'] = access_token.token
        hash['refresh_token'] = access_token.refresh_token if access_token.expires? && access_token.refresh_token
        hash['expires_at'] = access_token.expires_in if access_token.expires?
        hash['expires'] = access_token.expires?
        refresh_token_expires_at = Time.now.to_i + access_token.params['refresh_expires_in'].to_i
        hash['refresh_token_expires_at'] = refresh_token_expires_at
        hash
      end

      uid {
        raw_info["data"]["me"]["externalId"]
      }
      
      info do
        {
          display_name: raw_info['data']['me']['displayName']
        }
      end
      
      extra do
        {
          'raw_info' => raw_info
        }
      end
      
      def raw_info
        raw_info_url = "https://kit.snapchat.com/v1/me"
        @raw_info ||= access_token.post(
          raw_info_url, 
          mode: :header, 
          header_format: 'Bearer %s', 
          body: "{'query':'{me{displayName bitmoji{avatar} externalId}}'}",
          "Content-Type" => "application/json"
        ).parsed
        
        @raw_info || {'me' => {}}
      end

      def callback_url
        options[:redirect_uri] || full_host + script_name + callback_path
      end

      def token_params
        authorization = Base64.strict_encode64("#{options.client_id}:#{options.client_secret}")
        super.merge({
          headers: {
            "Authorization" => "Basic #{authorization}"
          }
        })
      end
    end
  end
end