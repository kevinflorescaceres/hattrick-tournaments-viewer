# frozen_string_literal: true

# Service to handle OAuth authentication for Hattrick API
class Authenticator < ApplicationService
  BASE_URL = 'https://chpp.hattrick.org'

  # Initializes the Authenticator service
  #
  # @raise [StandardError] if environment variables are missing
  def initialize
    @consumer_key = ENV['HATTRICK_CONSUMER_KEY']
    @consumer_secret = ENV['HATTRICK_CONSUMER_SECRET']
    set_consumer and return if @consumer_key && @consumer_secret

    raise StandardError, 'Missing HATTRICK_CONSUMER_KEY or HATTRICK_CONSUMER_SECRET'
  end

  # Returns self to allow method chaining
  #
  # @return [Authenticator]
  def call
    self
  end

  # Requests an OAuth request token
  #
  # @return [OAuth::RequestToken] the request token
  # @raise [OAuth::Unauthorized] if authentication fails
  def request_token
    Rails.logger.info '[AUTHENTICATOR] ** INIT GET REQUEST TOKEN **'
    oauth_callback = "#{Rails.application.config.root_url}oauths/access_token"
    @oauth_consumer.get_request_token(oauth_callback:)
  rescue OAuth::Unauthorized => e
    Rails.logger.error("OAuth error: #{e.message}")
    raise
  end

  # Exchanges a request token for an access token
  #
  # @param oauth_token_hash [Hash] the OAuth token hash
  # @param oauth_verifier [String] the OAuth verifier
  # @return [OAuth::AccessToken] the access token
  # @raise [OAuth::Unauthorized] if authentication fails
  def get_access_token(oauth_token_hash, oauth_verifier)
    Rails.logger.info '[AUTHENTICATOR] ** INIT GET ACCESS TOKEN **'
    request_token = OAuth::RequestToken.from_hash(@oauth_consumer, oauth_token_hash)
    request_token.get_access_token(oauth_verifier:)
  rescue OAuth::Unauthorized => e
    Rails.logger.error("OAuth error: #{e.message}")
    raise
  end

  # Builds an access token from a hash
  #
  # @param access_token_hash [Hash] the access token hash
  # @return [OAuth::AccessToken] the built access token
  # @raise [StandardError] if authentication fails
  def access_token_from_hash(access_token_hash)
    Rails.logger.info '[AUTHENTICATOR] ** INIT BUILD OAUTH ACCESS TOKEN FROM HASH **'
    OAuth::AccessToken.from_hash(@oauth_consumer, access_token_hash)
  rescue OAuth::Unauthorized => e
    message = "OAuth error while building access token: #{e.message}"
    Rails.logger.error(message)
    raise StandardError, message
  end

  private

  # Configures the OAuth consumer
  #
  # @return [void]
  # @set @oauth_consumer
  def set_consumer
    @oauth_consumer = OAuth::Consumer.new(@consumer_key, @consumer_secret,
                                          site: BASE_URL,
                                          request_token_path: '/oauth/request_token.ashx',
                                          authorize_path: '/oauth/authorize.aspx',
                                          authenticate_path: '/oauth/authenticate.aspx',
                                          access_token_path: '/oauth/access_token.ashx',
                                          http_method: :get,
                                          oauth_version: '1.0',
                                          body_hash_enabled: false,
                                          debug_output: $stdout)
  end
end
