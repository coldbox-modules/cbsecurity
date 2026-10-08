<cfscript>
	/**
	 * Retrieve the Jwt Auth Service
	 */
	function jwtAuth() {
        return wirebox.getInstance( "JwtService@cbSecurity" );
	}

	/**
	 * Retrieve the CBSecurity Service Object
	 */
	function cbSecure() {
        return wirebox.getInstance( "CBSecurity@cbSecurity" );
	}

	/**
	 * Build a signed URL for a named route. Params that match a route segment fill the pattern, the rest go in the query string.
	 *
	 * @name      The route name, same as `event.route()`
	 * @params    The route params
	 * @expiresIn Seconds until the link expires. Zero means never.
	 */
	string function signedRoute( required string name, struct params = {}, numeric expiresIn = 0 ) {
		var event     = getRequestContext();
		var found     = getInstance( "router@coldbox" ).findRouteByName( arguments.name );
		var pattern   = structKeyExists( found, "pattern" ) ? found.pattern : "";
		var routeKeys = {};
		var extras    = [];

		// Params that match a route segment fill the pattern, the rest become query params
		for ( var key in arguments.params ) {
			if ( reFindNoCase( ":" & key & "(\W|$)", pattern ) ) {
				routeKeys[ key ] = arguments.params[ key ];
			} else {
				extras.append( encodeForURL( key ) & "=" & encodeForURL( arguments.params[ key ] ) );
			}
		}

		var link = event.route( arguments.name, routeKeys );
		if ( extras.len() ) {
			link &= "?" & extras.toList( "&" );
		}
		return getInstance( "UrlSigner@cbsecurity" ).sign( link, arguments.expiresIn );
	}

	/**
	 * Build a signed URL for an event or route path, like `event.buildLink()` but with a real query string.
	 *
	 * @to          The event or route path
	 * @queryString Query string as a string or struct
	 * @expiresIn   Seconds until the link expires. Zero means never.
	 */
	string function signedUrl( required string to, any queryString = "", numeric expiresIn = 0 ) {
		var link = getRequestContext().buildLink(
			to          = arguments.to,
			queryString = arguments.queryString,
			translate   = false
		);
		return getInstance( "UrlSigner@cbsecurity" ).sign( link, arguments.expiresIn );
	}

	/**
	 * Does the current request carry a valid signed URL?
	 */
	boolean function hasValidSignature() {
		return getInstance( "UrlSigner@cbsecurity" ).checkRequest( getRequestContext() ) == "valid";
	}
</cfscript>
