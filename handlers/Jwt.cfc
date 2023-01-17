/**
 * This handler controls open endpoints for our JWT services
 */
component extends="coldbox.system.RestHandler" {

	// DI
	property name="jwtService" inject="jwtService@cbSecurity";

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
