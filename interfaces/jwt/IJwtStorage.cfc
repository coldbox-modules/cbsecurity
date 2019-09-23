/**
 * Copyright since 2016 by Ortus Solutions, Corp
 * www.ortussolutions.com
 * ---
 * If you will be building jwt token storages, then implement this interface
 */
interface{

    /**
     * Configure the storage by passing in the properties
     *
     * @return JWTStorage
     */
    any function configure( required properties );

    /**
     * Set a token in the storage
     *
     * @key The cache key
     * @token The token to store
     * @expiration The token expiration
	 * @payload The payload
     *
     * @return JWTStorage
     */
    any function set(
		required key,
		required token,
		required expiration,
		required payload
	);

    /**
     * Verify if the passed in token key exists
     *
     * @key The cache key
     */
    boolean function exists( required key );

    /**
     * Retrieve the token record via the cache key, if the key doesn't exist a TokenNotFoundException will be thrown
     *
     * @key The cache key
     * @defaultValue If not found, return a default value
     *
     * @throws TokenNotFoundException
	 *
	 * @return { cacheKey, token, expiration, created }
     */
    struct function get( required key, struct defaultValue );

    /**
     * Invalidate/delete one or more keys from the storage
     *
     * @key A cache key or an array of keys to clear
     *
     * @return true, if deleted, else false
     */
    boolean function clear( required any key );

    /**
     * Clear all the keys in the storage
     *
     * @async Run in a separate thread
     *
     * @return JWTStorage
     */
    any function clearAll( boolean async=false );

    /**
     * Retrieve all the jwt keys stored in the storage
     */
    array function keys();

    /**
     * The size of the storage
     */
    numeric function size();

}