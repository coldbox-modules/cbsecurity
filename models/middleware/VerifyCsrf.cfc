/**
 * Copyright since 2016 by Ortus Solutions, Corp
 * www.ortussolutions.com
 * ---
 * Route middleware that verifies a CSRF token on unsafe requests (anything except GET, HEAD and OPTIONS) using the
 * bundled cbcsrf module. The token is read from the `csrf` request collection key or the `x-csrf-token` header,
 * the same places the cbcsrf auto verifier uses. A missing or invalid token gets a 403.
 *
 * Route meta override: `csrfKey`, the key the token was generated for (default `default`).
 *
 * Unlike the cbcsrf auto verifier, this middleware also runs in integration tests.
 */
component extends="BaseMiddleware" {

	boolean function preProcess( required event, rc, prc ){
		if ( listFindNoCase( "GET,HEAD,OPTIONS", arguments.event.getHTTPMethod() ) ) {
			return false;
		}

		var token = arguments.event.getValue( "csrf", arguments.event.getHTTPHeader( "x-csrf-token", "" ) );
		var key   = getRouteMeta( arguments.event ).csrfKey ?: "default";

		if (
			isSimpleValue( token ) && len( token ) && variables.wirebox
				.getInstance( "@cbcsrf" )
				.verify( token, key )
		) {
			return false;
		}

		return deny(
			arguments.event,
			403,
			"The CSRF token is missing or invalid"
		);
	}

}
