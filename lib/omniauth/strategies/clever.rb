require 'omniauth-oauth2'
require 'base64'

module OmniAuth
  module Strategies
    class Clever < OmniAuth::Strategies::OAuth2
      CLEVER_API_VERSION = 'v2.1'

      # Clever is a unique OAuth 2.0 service provider in that login sequences
      # are often initiated by Clever, not the client. When Clever initiates
      # login, a state parameter is not relevant nor sent.

      option :name, "clever"
      option :client_options, {
        :site          => 'https://api.clever.com',
        :authorize_url => 'https://clever.com/oauth/authorize',
        :token_url     => 'https://clever.com/oauth/tokens'
      }

      # This option bubbles up to the OmniAuth::Strategies::OAuth2
      # when we call super in the callback_phase below.
      # **State will still be verified** when login is initiated by the client.
      option :provider_ignores_state, true

      def token_params
        super.tap do |params|
          params[:headers] = { 'Authorization' => "Basic #{Base64.strict_encode64("#{options.client_id}:#{options.client_secret}")}" }
        end
      end

      def callback_phase
        error = request.params["error_reason"] || request.params["error"]
        stored_state = session.delete("omniauth.state")
        if error
          fail!(error, CallbackError.new(request.params["error"], request.params["error_description"] || request.params["error_reason"], request.params["error_uri"]))
        else
          # Only verify state if we've initiated login and have stored a state
          # to compare to.
          if stored_state && (!request.params["state"] || request.params["state"] != stored_state)
            fail!(:csrf_detected, CallbackError.new(:csrf_detected, "CSRF detected"))
          else
            super
          end
        end
      end

      uid { raw_info.dig(:me, 'data', 'id') }

      info do
        personal_info = raw_info[:canonical]
        first_name = personal_info.dig('data', 'name', 'first')
        last_name = personal_info.dig('data', 'name', 'last')
        name = "#{first_name} #{last_name}".strip
        email = personal_info.dig('data', 'email')
        user_type = raw_info.dig(:me, 'type')
        # https://github.com/omniauth/omniauth/wiki/Auth-Hash-Schema
        info = {}
        info[:name] = name if name
        info[:first_name] = first_name if first_name
        info[:last_name] = last_name if last_name
        info[:email] = email if email
        info[:user_type] = user_type if user_type
        info
      end

      extra do
        {
          'raw_info' => raw_info
        }
      end

      def raw_info
        @raw_info ||= { me: me_response, canonical: canonical_response }
      end

      def me_response
        @me_response ||= access_token.get("/#{CLEVER_API_VERSION}/me").parsed
      end

      # Get personal information about the user, such as name and email.
      def canonical_response
        return @canonical_response if @canonical_response

        # https://dev.clever.com/v2.1/docs/data-model#links
        links = me_response['links']
        canonical_url = links.detect { |pair| pair['rel'] == 'canonical' }['uri']
        @canonical_response = access_token.get(canonical_url).parsed
      end

      # Fix unknown redirect uri bug by NOT appending the query string to the callback url.
      def callback_url
        full_host + script_name + callback_path
      end
    end
  end
end
