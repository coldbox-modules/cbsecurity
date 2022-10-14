/**
 * CbSecurity Handler Actions
 */
component extends="coldbox.system.RestHandler" {

	// DI
	property name="settings"   inject="coldbox:moduleSettings:cbsecurity";
	property name="jwtService" inject="jwtService@cbSecurity";

	/**
	 * Visualizer Action
	 */
	function index( event, rc, prc ){
		// If not enabled or in production, just 404 it
		if ( !variables.settings.visualizer.enabled || getSetting( "environment" ) == "production" ) {
			event.setHTTPHeader( statusCode = 404, statusText = "page not found" );
			return "Page Not Found";
		}
		prc.settings = variables.settings;
		// Show the visualizer
		event.setView( "home/index" );
	}

	/**
	 * Endpoint to refresh access tokens
	 *
	 * - x-refresh-token header or rc variable
	 */
	function refreshToken( event, rc, prc ){
		// If endpoint not enabled, just 404 it
		if ( !variables.jwtService.getSettings().jwt.enableRefreshEndpoint ) {
			return event
				.getResponse()
				.setErrorMessage(
					"Refresh Token Endpoint Disabled",
					404,
					"Disabled"
				);
		}

		try {
			// Do cool refreshments via header/rc discovery
			prc.newTokens = variables.jwtService.refreshToken();
			// Send valid response
			event
				.getResponse()
				.setData( prc.newTokens )
				.addMessage( "Tokens refreshed! The passed in refresh token has been invalidated" );
		} catch ( RefreshTokensNotActive e ) {
			return event.getResponse().setErrorMessage( "Refresh Tokens Not Active", 404, "Disabled" );
		} catch ( TokenNotFoundException e ) {
			return event
				.getResponse()
				.setErrorMessage(
					"The refresh token was not passed via the header or the rc. Cannot refresh the unrefreshable!",
					400,
					"Missing refresh token"
				);
		} catch ( TokenInvalidException e ) {
			prc.response.setErrorMessage(
				"Invalid Token - #e.message#",
				401,
				"Invalid Token"
			);
		} catch ( TokenExpiredException e ) {
			prc.response.setErrorMessage(
				"Token Expired - #e.message#",
				400,
				"Token Expired"
			);
		}
	}

}
