/**
 * Copyright since 2016 by Ortus Solutions, Corp
 * www.ortussolutions.com
 * ---
 * Route middleware that rate limits requests. Over the limit gets a 429 with a `Retry-After` header. Allowed
 * requests get `X-RateLimit-Limit` and `X-RateLimit-Remaining` headers.
 *
 * Use a named limiter from the `middleware.throttle.limiters` setting:
 *
 * <pre>
 * route( "/login" ).middleware( "Throttle@cbsecurity" ).meta( { throttle : "login" } ).to( "sessions.create" )
 * </pre>
 *
 * Or set the limits inline on the route. Unset values come from the `middleware.throttle` defaults:
 *
 * <pre>
 * .meta( { throttle : { maxAttempts : 10, decaySeconds : 60, by : "user", cacheProvider : "redis" } } )
 * </pre>
 *
 * Limiter keys:
 * - `maxAttempts`: requests per window
 * - `decaySeconds`: the window length
 * - `cacheProvider`: the CacheBox cache that counts (default `default`)
 * - `by`: `ip` (default) or `user`. `user` falls back to the IP for guests.
 * - `name`: groups routes under one counter (default: the limiter name, or the route pattern)
 */
component extends="BaseMiddleware" {

	property name="rateLimiter" inject="RateLimiter@cbsecurity";
	property name="cbSecurity"  inject="CBSecurity@cbsecurity";

	boolean function preProcess( required event, rc, prc ){
		var limit = resolveLimit( arguments.event );
		var key   = limit.name & ":" & identify( arguments.event, limit.by );
		var cache = limit.cacheProvider;

		if ( variables.rateLimiter.tooManyAttempts( key, limit.maxAttempts, cache ) ) {
			return deny(
				arguments.event,
				429,
				"Too many requests",
				{
					"Retry-After"           : variables.rateLimiter.availableIn( key, cache ),
					"X-RateLimit-Limit"     : limit.maxAttempts,
					"X-RateLimit-Remaining" : 0
				}
			);
		}

		variables.rateLimiter.hit( key, limit.decaySeconds, cache );

		arguments.event.setHTTPHeader( name = "X-RateLimit-Limit", value = limit.maxAttempts );
		arguments.event.setHTTPHeader(
			name  = "X-RateLimit-Remaining",
			value = variables.rateLimiter.remaining( key, limit.maxAttempts, cache )
		);
		return false;
	}

	/**
	 * Build the limit from the defaults, the named limiter and the route meta
	 */
	private struct function resolveLimit( required event ){
		var config = getMiddlewareSettings( "throttle" );
		var meta   = getRouteMeta( arguments.event );
		var spec   = structKeyExists( meta, "throttle" ) ? meta.throttle : {};
		var limit  = {
			"maxAttempts"   : config.maxAttempts,
			"decaySeconds"  : config.decaySeconds,
			"cacheProvider" : config.cacheProvider,
			"by"            : "ip",
			"name"          : ""
		};

		// A string names a limiter
		if ( isSimpleValue( spec ) ) {
			if ( len( spec ) ) {
				if ( !structKeyExists( config, "limiters" ) || !structKeyExists( config.limiters, spec ) ) {
					misconfigured( "The throttle limiter [#spec#] is not defined in [middleware.throttle.limiters]" );
				}
				limit.name = spec;
				spec       = config.limiters[ spec ];
			} else {
				spec = {};
			}
		}
		limit.append( spec, true );

		if ( !listFindNoCase( "ip,user", limit.by ) ) {
			misconfigured( "The throttle [by] value [#limit.by#] is invalid. Use ip or user" );
		}
		if ( !len( limit.name ) ) {
			limit.name = arguments.event.getPrivateValue( "currentRoute", arguments.event.getCurrentEvent() );
		}
		return limit;
	}

	/**
	 * Who are we counting
	 */
	private string function identify( required event, required string by ){
		if ( arguments.by == "user" && variables.cbSecurity.isLoggedIn() ) {
			return "user-" & variables.cbSecurity.getUser().getId();
		}
		return "ip-" & getClientIP( arguments.event );
	}

}
