/**
 * Copyright since 2016 by Ortus Solutions, Corp
 * www.ortussolutions.com
 * ---
 * Base class for the cbsecurity route middleware that do not authenticate users: EnsureHttps, AllowedIPs, DenyIPs,
 * ApiKey, Honeypot, VerifyCsrf, Throttle and Signed.
 *
 * Settings come from `moduleSettings.cbsecurity.middleware` and every value can be overridden per route with `.meta()`.
 * Returning true from `preProcess()` tells ColdBox to skip the rest of the route's middleware.
 */
component accessors="true" {

	// DI
	property name="wirebox"  inject="wirebox";
	property name="settings" inject="coldbox:moduleSettings:cbsecurity";

	/**
	 * Get the metadata of the current route
	 */
	struct function getRouteMeta( required event ){
		return arguments.event.getPrivateValue( "currentRouteMeta", {} );
	}

	/**
	 * Get the middleware settings for one middleware, e.g. `apiKey`
	 */
	struct function getMiddlewareSettings( required string name ){
		return structKeyExists( variables.settings.middleware, arguments.name ) ? variables.settings.middleware[
			arguments.name
		] : {};
	}

	/**
	 * Normalize a list or array into a trimmed array without empty items
	 */
	array function toArray( required any value ){
		var items = isArray( arguments.value ) ? arguments.value : listToArray( arguments.value );
		return items.map( ( item ) => trim( item ) ).filter( ( item ) => len( item ) );
	}

	/**
	 * Compare two strings in constant time
	 */
	boolean function safeEquals( required string a, required string b ){
		return createObject( "java", "java.security.MessageDigest" ).isEqual(
			arguments.a.getBytes( "UTF-8" ),
			arguments.b.getBytes( "UTF-8" )
		);
	}

	/**
	 * Stops the request and renders a JSON error. Always returns true so you can `return deny( ... )`.
	 *
	 * @event      The request context
	 * @statusCode The HTTP status code
	 * @message    The error message
	 * @headers    Extra response headers as name-value pairs
	 */
	boolean function deny(
		required event,
		numeric statusCode = 403,
		string message     = "Forbidden",
		struct headers     = {}
	){
		for ( var name in arguments.headers ) {
			arguments.event.setHTTPHeader( name = name, value = arguments.headers[ name ] );
		}
		arguments.event
			.renderData(
				type       = "json",
				data       = { "error" : true, "messages" : [ arguments.message ] },
				statusCode = arguments.statusCode
			)
			.noExecution();
		return true;
	}

	/**
	 * The address that made the TCP connection
	 */
	string function getRemoteAddr(){
		return len( cgi.remote_addr ) ? trim( listFirst( cgi.remote_addr ) ) : "127.0.0.1";
	}

	/**
	 * Get the client IP. The X-Forwarded-For header is only honored when the connection comes from a trusted proxy
	 * (`middleware.trustedProxies`). We walk the header from the right and return the first address that is not a trusted proxy.
	 *
	 * @event The request context
	 */
	string function getClientIP( required event ){
		var remote  = getRemoteAddr();
		var proxies = toArray( variables.settings.middleware.trustedProxies );

		if ( !proxies.len() || !ipMatchesAny( remote, proxies ) ) {
			return remote;
		}

		var chain = listToArray( arguments.event.getHTTPHeader( "X-Forwarded-For", "" ) )
			.map( ( item ) => trim( item ) )
			.filter( ( item ) => len( item ) );
		for ( var i = chain.len(); i >= 1; i-- ) {
			if ( !ipMatchesAny( chain[ i ], proxies ) ) {
				return chain[ i ];
			}
		}
		return remote;
	}

	/**
	 * Does an IP match any of the rules? A rule is an exact IP or a CIDR range, IPv4 or IPv6.
	 *
	 * @ip    The IP to test
	 * @rules An array of IPs or CIDR ranges
	 */
	boolean function ipMatchesAny( required string ip, required array rules ){
		for ( var rule in arguments.rules ) {
			if ( ipMatches( arguments.ip, rule ) ) {
				return true;
			}
		}
		return false;
	}

	/**
	 * Does an IP match one rule? Invalid input never matches.
	 */
	boolean function ipMatches( required string ip, required string rule ){
		try {
			var inet      = createObject( "java", "java.net.InetAddress" );
			var ipBytes   = inet.getByName( trim( arguments.ip ) ).getAddress();
			var ruleParts = listToArray( trim( arguments.rule ), "/" );
			var ruleBytes = inet.getByName( ruleParts[ 1 ] ).getAddress();

			// A different family (v4 vs v6) never matches
			if ( arrayLen( ipBytes ) != arrayLen( ruleBytes ) ) {
				return false;
			}

			var prefix = ruleParts.len() > 1 ? val( ruleParts[ 2 ] ) : arrayLen( ruleBytes ) * 8;
			if ( prefix < 0 || prefix > arrayLen( ruleBytes ) * 8 ) {
				return false;
			}

			for ( var i = 1; i <= arrayLen( ruleBytes ); i++ ) {
				var bits = min( 8, max( 0, prefix - ( ( i - 1 ) * 8 ) ) );
				if ( bits == 0 ) {
					break;
				}
				var mask = bitAnd( bitShln( 255, 8 - bits ), 255 );
				if ( bitAnd( ipBytes[ i ], mask ) != bitAnd( ruleBytes[ i ], mask ) ) {
					return false;
				}
			}
			return true;
		} catch ( any e ) {
			return false;
		}
	}

	/**
	 * Throw a configuration error
	 */
	function misconfigured( required string message ){
		throw( type = "cbsecurity.MiddlewareMisconfigured", message = arguments.message );
	}

}
