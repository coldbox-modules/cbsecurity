/**
 * Copyright since 2016 by Ortus Solutions, Corp
 * www.ortussolutions.com
 * ---
 * Route middleware that requires an API key. It looks in a request header first (default `x-api-key`) and then in the
 * request collection (default `apiKey`). A missing or invalid key gets a 401.
 *
 * Valid keys come from, in order:
 * - the route meta key `apiKeys` (a list or array)
 * - the `middleware.apiKey.keys` setting
 * - a WireBox validator, `middleware.apiKey.validator`, that implements `boolean isValidKey( required string key, required event )`
 *
 * Route meta overrides: `apiKeyHeader`, `apiKeyParam` and `apiKeys`.
 *
 * Do not keep keys in source control. Load them from environment variables in your configuration.
 */
component extends="BaseMiddleware" {

	boolean function preProcess( required event, rc, prc ){
		var config    = getMiddlewareSettings( "apiKey" );
		var header    = getMetaValue( arguments.event, "apiKeyHeader", config.header );
		var param     = getMetaValue( arguments.event, "apiKeyParam", config.param );
		var keys      = toArray( getMetaValue( arguments.event, "apiKeys", config.keys ) );
		var validator = structKeyExists( config, "validator" ) ? config.validator : "";

		if ( !keys.len() && !len( validator ) ) {
			misconfigured(
				"ApiKey requires keys: use the route meta [apiKeys], the [middleware.apiKey.keys] setting or a [middleware.apiKey.validator]"
			);
		}

		// Header first, then the request collection
		var incoming = len( header ) ? arguments.event.getHTTPHeader( header, "" ) : "";
		if ( !len( incoming ) && len( param ) ) {
			incoming = arguments.event.getValue( param, "" );
		}

		if (
			isSimpleValue( incoming ) && len( incoming ) && isValidKey(
				trim( incoming ),
				keys,
				validator,
				arguments.event
			)
		) {
			return false;
		}

		return deny(
			arguments.event,
			401,
			"A valid API key is required"
		);
	}

	/**
	 * Verify the key against the static keys and then the validator
	 */
	private boolean function isValidKey(
		required string key,
		required array keys,
		required string validator,
		required event
	){
		// Check every key so timing does not reveal which one matched
		var found = false;
		for ( var candidate in arguments.keys ) {
			if ( safeEquals( arguments.key, candidate ) ) {
				found = true;
			}
		}
		if ( found ) {
			return true;
		}

		if ( len( arguments.validator ) ) {
			return variables.wirebox
				.getInstance( arguments.validator )
				.isValidKey( arguments.key, arguments.event );
		}
		return false;
	}

}
