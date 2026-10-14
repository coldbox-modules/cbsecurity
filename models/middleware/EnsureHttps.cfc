/**
 * Copyright since 2016 by Ortus Solutions, Corp
 * www.ortussolutions.com
 * ---
 * Route middleware that forces HTTPS. GET and HEAD requests are redirected with a 301, any other method is denied
 * with a 403 because a redirect would drop the request body.
 *
 * Detection uses `event.isSSL()`, which honors the usual proxy headers (X-Forwarded-Proto and X-Scheme).
 *
 * Settings: `middleware.ensureHttps.redirect` (default true). Route meta override: `redirectToHttps` (boolean).
 */
component extends="BaseMiddleware" {

	boolean function preProcess( required event, rc, prc ){
		if ( arguments.event.isSSL() ) {
			return false;
		}

		var routeMeta = getRouteMeta( arguments.event );
		var redirect  = routeMeta.keyExists( "redirectToHttps" ) ? routeMeta.redirectToHttps : getMiddlewareSettings(
			"ensureHttps"
		).redirect;

		if ( redirect && listFindNoCase( "GET,HEAD", arguments.event.getHTTPMethod() ) ) {
			// getUrl() replaced getFullUrl() in ColdBox 8
			var currentUrl = structKeyExists( arguments.event, "getUrl" ) ? arguments.event.getUrl() : arguments.event.getFullUrl();
			arguments.event.relocate( URL = replaceNoCase( currentUrl, "http:", "https:" ), statusCode = 301 );
			return true;
		}

		return deny( arguments.event, 403, "HTTPS is required" );
	}

}
