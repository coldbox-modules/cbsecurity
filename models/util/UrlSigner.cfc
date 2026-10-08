/**
 * Copyright since 2016 by Ortus Solutions, Corp
 * www.ortussolutions.com
 * ---
 * Signs URLs and verifies them. A signed URL carries an HMAC-SHA256 signature of its path and query string, so
 * nobody can change the path or a parameter, and an optional expiration time, without invalidating it.
 *
 * <pre>
 * signer = getInstance( "UrlSigner@cbsecurity" )
 * link   = signer.sign( "https://example.com/invoices/42/download", 3600 )
 * signer.isValid( link ) // true until the hour is up
 * </pre>
 *
 * What is signed: the URL path and every query parameter except the signature, with parameters sorted by name.
 * Parameter names are case insensitive, a trailing slash on the path is ignored, and the scheme, host and fragment are ignored, so a URL still validates behind proxies and load balancers.
 *
 * Settings (`moduleSettings.cbsecurity.signedUrls`): `secret` (required), `signatureParam` and `expiresParam`.
 */
component accessors="true" singleton threadSafe {

	// DI
	property name="settings" inject="coldbox:moduleSettings:cbsecurity";

	function init(){
		return this;
	}

	/**
	 * Sign a URL, absolute or relative. Any signature or expiration already on it is replaced.
	 *
	 * @url       The URL to sign
	 * @expiresIn Seconds from now until the link expires. Zero means it never expires.
	 *
	 * @return The URL with the expiration (if any) and signature added to its query string
	 */
	string function sign( required string url, numeric expiresIn = 0 ){
		var config = getConfig();
		var target = listFirst( arguments.url, "##" );
		var base   = listFirst( target, "?" );
		var pairs  = parsePairs( find( "?", target ) ? listRest( target, "?" ) : "" ).filter( ( pair ) => {
			return compareNoCase( pair.name, config.signatureParam ) != 0 && compareNoCase(
				pair.name,
				config.expiresParam
			) != 0;
		} );

		if ( arguments.expiresIn > 0 ) {
			pairs.append( {
				"name"  : config.expiresParam,
				"value" : nowInSeconds() + int( arguments.expiresIn )
			} );
		}

		var signature = computeSignature( base, pairs );
		pairs.append( { "name" : config.signatureParam, "value" : signature } );

		return base & "?" & pairs
			.map( ( pair ) => encodeForURL( pair.name ) & "=" & encodeForURL( pair.value ) )
			.toList( "&" );
	}

	/**
	 * Verify a URL
	 *
	 * @url The URL to verify, absolute or relative
	 */
	boolean function isValid( required string url ){
		return check( arguments.url ) == "valid";
	}

	/**
	 * Verify a URL and say why it failed
	 *
	 * @url The URL to verify, absolute or relative
	 *
	 * @return valid, missing (no signature), invalid (the URL was altered) or expired
	 */
	string function check( required string url ){
		var config = getConfig();
		var target = listFirst( arguments.url, "##" );
		var base   = listFirst( target, "?" );
		var all    = parsePairs( find( "?", target ) ? listRest( target, "?" ) : "" );

		var given = all.filter( ( pair ) => compareNoCase( pair.name, config.signatureParam ) == 0 );
		if ( !given.len() ) {
			return "missing";
		}

		var signed = all.filter( ( pair ) => compareNoCase( pair.name, config.signatureParam ) != 0 );
		if ( !safeEquals( given[ 1 ].value, computeSignature( base, signed ) ) ) {
			return "invalid";
		}

		var expires = signed.filter( ( pair ) => compareNoCase( pair.name, config.expiresParam ) == 0 );
		if ( expires.len() ) {
			if ( !isNumeric( expires[ 1 ].value ) || expires[ 1 ].value <= nowInSeconds() ) {
				return "expired";
			}
		}
		return "valid";
	}

	/**
	 * Rebuild the URL of the current request the same way `event.buildLink()` and `event.route()` build links. The
	 * query string comes from the `URL` scope.
	 *
	 * @event The request context
	 */
	string function requestUrl( required event ){
		var query = [];
		for ( var key in url ) {
			if ( isSimpleValue( url[ key ] ) ) {
				query.append( encodeForURL( key ) & "=" & encodeForURL( url[ key ] ) );
			}
		}
		return arguments.event.getSESBaseURL() & "/" & arguments.event.getCurrentRoutedURL() & (
			query.len() ? "?" & query.toList( "&" ) : ""
		);
	}

	/**
	 * Verify the URL of the current request
	 *
	 * @event The request context
	 *
	 * @return valid, missing, invalid or expired
	 */
	string function checkRequest( required event ){
		return check( requestUrl( arguments.event ) );
	}

	/************************************ PRIVATE ************************************/

	/**
	 * Signature of the canonical form: the decoded path, a question mark and the sorted `name=value` pairs
	 */
	private string function computeSignature( required string base, required array pairs ){
		var secret = getConfig().secret;
		// Names are lower cased because engines upper case the keys of the URL scope
		var items  = arguments.pairs.map( ( pair ) => lCase( pair.name ) & "=" & pair.value );
		arraySort( items, "text" );
		return lCase(
			hmac(
				normalizePath( arguments.base ) & "?" & items.toList( "&" ),
				secret,
				"HMACSHA256"
			)
		);
	}

	/**
	 * Drop the scheme and host, collapse repeated slashes and decode
	 */
	private string function normalizePath( required string base ){
		var path = reReplace(
			arguments.base,
			"^[a-zA-Z][a-zA-Z0-9+.\-]*://[^/]*",
			""
		);
		path = reReplace( path, "/{2,}", "/", "all" );
		path = urlDecode( path );
		path = left( path, 1 ) == "/" ? path : "/" & path;
		// A trailing slash does not change the route
		return len( path ) > 1 && right( path, 1 ) == "/" ? left( path, len( path ) - 1 ) : path;
	}

	/**
	 * Parse a query string into an array of decoded name-value pairs
	 */
	private array function parsePairs( required string query ){
		return listToArray( arguments.query, "&" ).map( ( item ) => {
			return {
				"name"  : urlDecode( listFirst( item, "=" ) ),
				"value" : find( "=", item ) ? urlDecode( listRest( item, "=" ) ) : ""
			};
		} );
	}

	private struct function getConfig(){
		var config = variables.settings.signedUrls;
		if ( !len( config.secret ?: "" ) ) {
			throw(
				type    = "cbsecurity.SigningSecretMissing",
				message = "Signed URLs need a secret. Set [signedUrls.secret] in your cbsecurity module settings, for example from the CBSECURITY_SIGNING_SECRET environment variable."
			);
		}
		return config;
	}

	private boolean function safeEquals( required string a, required string b ){
		return createObject( "java", "java.security.MessageDigest" ).isEqual(
			arguments.a.getBytes( "UTF-8" ),
			arguments.b.getBytes( "UTF-8" )
		);
	}

	private numeric function nowInSeconds(){
		return int( createObject( "java", "java.lang.System" ).currentTimeMillis() / 1000 );
	}

}
