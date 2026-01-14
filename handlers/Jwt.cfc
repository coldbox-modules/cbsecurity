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
			event.getResponse().setErrorMessage( "Refresh Token Endpoint Disabled", 404 );
			return;
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
			event.getResponse().setErrorMessage( "Refresh Tokens Not Active", 404 );
		} catch ( TokenNotFoundException e ) {
			event
				.getResponse()
				.setErrorMessage(
					"The refresh token was not passed via the header or the rc. Cannot refresh the unrefreshable!",
					400
				);
		} catch ( TokenInvalidException e ) {
			event.getResponse().setErrorMessage( "Invalid Token", 401 );
		} catch ( TokenExpiredException e ) {
			event.getResponse().setErrorMessage( "Token Expired", 400 );
		} catch ( TokenRejectionException e ) {
			event.getResponse().setErrorMessage( "Invalid Token", 401 );
		}
	}

}
