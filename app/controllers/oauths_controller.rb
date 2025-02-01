# frozen_string_literal: true

# Handles OAuth authentication flow
class OauthsController < ApplicationController
  before_action :set_root_url
  before_action :set_authenticator

  # Initiates the OAuth request token flow and stores the token and secret in session and redirects to authorization URL
  #
  # @return [void]
  def request_token
    request_token = @authenticator.request_token
    session[:token] = request_token.token
    session[:token_secret] = request_token.secret
    redirect_to request_token.authorize_url(oauth_callback: 'oob'), allow_other_host: true
  end

  # Exchanges the request token for an access token. Stores the access token in session and removes the temporary tokens
  #
  # @raise [OAuth::Unauthorized] if authentication fails
  # @return [void]
  def access_token
    hash = { oauth_token: session[:token], oauth_token_secret: session[:token_secret] }
    verifier = params[:oauth_verifier]
    access_token = @authenticator.get_access_token(hash, verifier)
    session[:access_token] = access_token.token
    session[:access_token_secret] = access_token.secret
    session.delete(:token)
    session.delete(:token_secret)
    redirect_to root_path, notice: 'Successful access'
  rescue OAuth::Unauthorized => e
    Rails.logger.error("OAuth error: #{e.message}")
    raise
  end

  private

  # Sets the application's root URL configuration
  #
  # @return [void]
  def set_root_url
    Rails.application.config.root_url = root_url
  end

  # Initializes the authenticator instance
  #
  # @return [void]
  # @set @authenticator
  def set_authenticator
    @authenticator = Authenticator.call
  end
end
