/**
 * Copyright since 2016 by Ortus Solutions, Corp
 * www.ortussolutions.com
 * ---
 * A CacheBox cache based token storage
 */
component accessors="true" singleton threadsafe {

	// DI
	property name="wirebox"    inject="wirebox";
	property name="cachebox"   inject="cachebox";
	property name="settings"   inject="coldbox:moduleSettings:cbSecurity";
	property name="jwtService" inject="JwtService@cbSecurity";

	/**
	 * Storage properties
	 */
	property name="properties";

	/**
	 * The linked cache provider
	 */
	property name="cache";

	/**
	 * The configured key prefix for the storage
	 */
	property name="keyPrefix";

	/**
	 * Constructor
	 */
	function init(){
		variables.settings = {};
		return this;
	}

	/**
	 * Configure the storage by passing in the properties
	 *
	 * @properties The storage properties
	 *
	 * @return JWTStorage
	 */
	any function configure( required properties ){
		variables.properties = arguments.properties;
		variables.cache      = variables.cachebox.getCache( variables.properties.cacheName );
		variables.keyPrefix  = variables.settings.jwt.tokenStorage.keyPrefix;

		return this;
	}

	/**
	 * Set a token in the storage
	 *
	 * @key        The cache key
	 * @token      The token to store
	 * @expiration The token expiration
	 * @payload    The payload
	 *
	 * @return JWTStorage
	 */
	any function set(
		required key,
		required token,
		required expiration,
		required payload
	){
		variables.cache.set(
			objectKey = buildKey( arguments.key ),
			object    = {
				token      : arguments.token,
				expiration : jwtService.fromEpoch( arguments.payload.exp ),
				issued     : jwtService.fromEpoch( arguments.payload.iat ),
				payload    : arguments.payload
			},
			timeout           = arguments.expiration,
			lastAccessTimeout = 0
		);
		return this;
	}

	/**
	 * Verify if the passed in token key exists
	 *
	 * @key The cache key
	 */
	boolean function exists( required key ){
		return variables.cache.lookup( buildKey( arguments.key ) );
	}

	/**
	 * Retrieve the token via the cache key, if the key doesn't exist a TokenNotFoundException will be thrown
	 *
	 * @key          The cache key
	 * @defaultValue If not found, return a default value
	 *
	 * @throws TokenNotFoundException
	 */
	struct function get( required key, struct defaultValue ){
		var results = variables.cache.get( buildKey( arguments.key ) );
		// return results
		if ( !isNull( results ) ) {
			results[ "cacheKey" ] = buildKey( arguments.key );
			return results;
		}

		// Default value
		if ( !isNull( arguments.defaultValue ) ) {
			return arguments.defaultValue;
		}
	}

	/**
	 * Invalidate/delete one or more keys from the storage
	 *
	 * @key A cache key or an array of keys to clear
	 *
	 * @return True, if deleted
	 */
	boolean function clear( required any key ){
		return variables.cache.clear( buildKey( arguments.key ) );
	}

	/**
	 * Clear all the keys in the storage
	 *
	 * @return JWTStorage
	 */
	any function clearAll(){
		variables.cache.clearAll();

		return this;
	}

	/**
	 * Retrieve all the jwt keys stored in the storage
	 */
	array function keys(){
		return variables.cache
			.getKeys()
			.filter( function( item ){
				return item.findNoCase( variables.keyPrefix );
			} );
	}

	/**
	 * The size of the storage
	 */
	numeric function size(){
		return variables.cache
			.getKeys()
			.filter( function( item ){
				return item.findNoCase( variables.keyPrefix );
			} )
			.len();
	}

	/**
	 * Build out a prefixed key
	 */
	private function buildKey( required key ){
		return variables.keyPrefix & arguments.key;
	}

}
