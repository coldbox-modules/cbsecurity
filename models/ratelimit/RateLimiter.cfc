/**
 * Copyright since 2016 by Ortus Solutions, Corp
 * www.ortussolutions.com
 * ---
 * A cache backed, fixed window rate limiter. Use it directly for anything that is not a route, like login attempts,
 * password resets or API calls inside a service. The `Throttle@cbsecurity` middleware is built on top of it.
 *
 * <pre>
 * limiter = getInstance( "RateLimiter@cbsecurity" )
 * if ( limiter.tooManyAttempts( "login:#rc.email#", 5 ) ) {
 *     // wait limiter.availableIn( "login:#rc.email#" ) seconds
 * }
 * limiter.hit( "login:#rc.email#", 60 )
 * </pre>
 *
 * Keys are stored in a CacheBox cache. Use a shared cache (Redis, Couchbase, a database) when you run more than one
 * server, otherwise every server counts on its own.
 */
component singleton threadSafe {

	// DI
	property name="cachebox" inject="cachebox";

	// The prefix of every cache key
	variables.KEY_PREFIX = "cbsecurity-ratelimit-";

	function init(){
		return this;
	}

	/**
	 * Record an attempt. A key starts its window with its first hit.
	 *
	 * @key           The key to limit, e.g. `login:127.0.0.1`
	 * @decaySeconds  How long the window lasts
	 * @cacheProvider The name of the CacheBox cache to use
	 *
	 * @return The number of attempts in the current window
	 */
	numeric function hit(
		required string key,
		numeric decaySeconds = 60,
		string cacheProvider = "default"
	){
		lock name="#variables.KEY_PREFIX##hash( arguments.key )#" type="exclusive" timeout="5" throwOnTimeout="true" {
			var record = readRecord( arguments.key, arguments.cacheProvider );
			var now    = nowInSeconds();

			if ( isNull( record ) ) {
				record = { "attempts" : 0, "resetAt" : now + arguments.decaySeconds };
			}
			record.attempts++;

			getCache( arguments.cacheProvider ).set(
				variables.KEY_PREFIX & arguments.key,
				record,
				ceiling( ( record.resetAt - now ) / 60 ) + 1,
				0
			);
		}
		return record.attempts;
	}

	/**
	 * Has the key reached its limit?
	 */
	boolean function tooManyAttempts(
		required string key,
		required numeric maxAttempts,
		string cacheProvider = "default"
	){
		return attempts( arguments.key, arguments.cacheProvider ) >= arguments.maxAttempts;
	}

	/**
	 * Attempts made in the current window
	 */
	numeric function attempts( required string key, string cacheProvider = "default" ){
		var record = readRecord( arguments.key, arguments.cacheProvider );
		return isNull( record ) ? 0 : record.attempts;
	}

	/**
	 * Attempts left in the current window, never below zero
	 */
	numeric function remaining(
		required string key,
		required numeric maxAttempts,
		string cacheProvider = "default"
	){
		return max( 0, arguments.maxAttempts - attempts( arguments.key, arguments.cacheProvider ) );
	}

	/**
	 * Seconds until the window resets, zero if there is no window
	 */
	numeric function availableIn( required string key, string cacheProvider = "default" ){
		var record = readRecord( arguments.key, arguments.cacheProvider );
		return isNull( record ) ? 0 : max( 0, record.resetAt - nowInSeconds() );
	}

	/**
	 * Reset a key, e.g. after a successful login
	 */
	RateLimiter function clear( required string key, string cacheProvider = "default" ){
		getCache( arguments.cacheProvider ).clear( variables.KEY_PREFIX & arguments.key );
		return this;
	}

	/**
	 * Read the live record or null. Expired windows are removed.
	 */
	private function readRecord( required string key, required string cacheProvider ){
		var cache  = getCache( arguments.cacheProvider );
		var record = cache.get( variables.KEY_PREFIX & arguments.key );

		if ( isNull( record ) ) {
			return;
		}
		if ( record.resetAt <= nowInSeconds() ) {
			cache.clear( variables.KEY_PREFIX & arguments.key );
			return;
		}
		return record;
	}

	private function getCache( required string name ){
		return variables.cachebox.getCache( arguments.name );
	}

	/**
	 * Epoch seconds
	 */
	private numeric function nowInSeconds(){
		return int( createObject( "java", "java.lang.System" ).currentTimeMillis() / 1000 );
	}

}
