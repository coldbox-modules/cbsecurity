/**
 * CbSecurity Handler Actions
 */
component extends="coldbox.system.RestHandler" {

	// DI
	property name="cbSecurity" inject="coldbox:interceptor:cbsecurity@global";
	property name="jwtService" inject="jwtService@cbSecurity";

	/**
	 * Visualizer Action
	 */
	function index( event, rc, prc ){
		prc.properties = variables.cbSecurity.getProperties();

		// If not enabled or in production, just 404 it
		if ( !prc.properties.enableSecurityVisualizer || getSetting( "environment" ) == "production" ) {
			event.setHTTPHeader( statusCode = 404, statusText = "page not found" );
			return "Page Not Found";
		}
		// Show the visualizer
		event.setView( "home/index" );
	}

	/**
	 * Endpoint to refresh access tokens
	 *
	 * - x-refresh-token header or rc variable
	 */
	function refreshToken( event, rc, prc ){
		prc.properties = variables.cbSecurity.getProperties();

		// If endpoint not enabled, just 404 it
		if ( !prc.properties.jwt.enableRefreshEndpoint ) {
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
			return event
				.getResponse()
				.setErrorMessage( "Refresh Tokens Not Active", 404, "Disabled" );
		} catch ( TokenNotFoundException e ) {
			return event
				.getResponse()
				.setErrorMessage(
					"The refresh token was not passed via the header or the rc. Cannot refresh the unrefreshable!",
					400,
					"Missing refresh token"
				);
		}
	}

}
