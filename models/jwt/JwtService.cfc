/**
 * Copyright since 2016 by Ortus Solutions, Corp
 * www.ortussolutions.com
 * ---
 * This is the JWT Services that will provide you with glorious JWT capabilities.
 * Learn more about Json Web Tokens here: https://jwt.io/
 */
component accessors="true" singleton threadsafe {

	/*********************************************************************************************/
	/** DI **/
	/*********************************************************************************************/

	property name="jwt"                inject="provider:jwt@jwtcfml";
	property name="wirebox"            inject="wirebox";
	property name="settings"           inject="coldbox:moduleSettings:cbSecurity";
	property name="interceptorService" inject="coldbox:interceptorService";
	property name="requestService"     inject="coldbox:requestService";
	property name="log"                inject="logbox:logger:{this}";
	property name="cbsecurity"         inject="@cbSecurity";

	/*********************************************************************************************/
	/** PROPERTIES **/
	/*********************************************************************************************/

	/**
	 * The token storage provider
	 */
	property name="tokenStorage";

	/*********************************************************************************************/
	/** STATIC PROPERTIES **/
	/*********************************************************************************************/

	// Required Claims
	variables.REQUIRED_CLAIMS = [ "jti", "iss", "iat", "sub", "exp", "scope" ];

	// Default JWT Settings
	variables.DEFAULT_SETTINGS = {
		// The jwt token issuer claim -> iss
		"issuer"                     : "",
		// The jwt secret encoding key
		"secretKey"                  : "",
		// The Custom header to inspect for tokens
		"customAuthHeader"           : "x-auth-token",
		// The expiration in minutes for the jwt tokens
		"expiration"                 : 60,
		// If true, enables refresh tokens, token creation methods will return a struct instead
		// of just the access token. e.g. { access_token: "", refresh_token : "" }
		"enableRefreshTokens"        : false,
		// The default expiration for refresh tokens, defaults to 30 days
		"refreshExpiration"          : 10080,
		// The Custom header to inspect for refresh tokens
		"customRefreshHeader"        : "x-refresh-token",
		// If enabled, the JWT validator will inspect the request for refresh tokens and expired access tokens
		// It will then automatically refresh them for you and return them back as
		// response headers in the same request according to the customRefreshHeader and customAuthHeader
		"enableAutoRefreshValidator" : false,
		// Enable the POST > /cbsecurity/refreshtoken API endpoint
		"enableRefreshEndpoint"      : true,
		// encryption algorithm to use, valid algorithms are: HS256, HS384, and HS512
		"algorithm"                  : "HS512",
		// Which claims neds to be present on the jwt token or `TokenInvalidException` upon verification and decoding
		"requiredClaims"             : [],
		// The token storage settings
		"tokenStorage"               : {
			// enable or not, default is true
			"enabled"    : true,
			// A cache key prefix to use when storing the tokens
			"keyPrefix"  : "cbjwt_",
			// The driver to use: db, cachebox or a WireBox ID
			"driver"     : "cachebox",
			// Driver specific properties
			"properties" : { "cacheName" : "default" }
		}
	};

	/*********************************************************************************************/
	/** CONSTRUCTOR & STARTUP **/
	/*********************************************************************************************/

	/**
	 * Constructor
	 */
	function init(){
		return this;
	}

	/**
	 * Runs after DI, here is where we setup the jwt settings for operation
	 */
	function onDIComplete(){
		// If no settings defined, use the defaults
		if ( !structKeyExists( variables.settings, "jwt" ) ) {
			variables.settings.jwt = variables.DEFAULT_SETTINGS;
		}

		// Incorporate defaults into incoming data
		structAppend(
			variables.settings.jwt,
			variables.DEFAULT_SETTINGS,
			false
		);
		structAppend(
			variables.settings.jwt.tokenStorage,
			variables.DEFAULT_SETTINGS.tokenStorage,
			false
		);

		// If no secret is defined, then let's create one dynamically
		if ( isNull( variables.settings.jwt.secretKey ) || !len( variables.settings.jwt.secretKey ) ) {
			variables.settings.jwt.secretKey = generateSecretKey( "blowfish", 448 );
			variables.log.warn( "No jwt secret key setting found, automatically generating one" );
		}

		// Check if issuer is set, if not, default to the home page URI
		if ( !len( variables.settings.jwt.issuer ) ) {
			variables.settings.jwt.issuer = variables.requestService.getContext().buildLink( "" );
		}
	}

	/************************************************************************************/
	/****************************** TOKEN CREATION METHODS ******************************/
	/************************************************************************************/

	/**
	 * Attempt to authenticate a user with the auth service and if succesful return a jwt token
	 * using the information in the authenticated user. If refresh tokens are enabled then you will
	 * get a struct of <code>{ access_token : "", refresh_token : "" }</code>
	 *
	 * @username            The username to use
	 * @password            The password to use
	 * @customClaims        A struct of custom claims to add to the jwt token if successful.
	 * @refreshCustomClaims A struct of custom claims to add to the refresh token if successful.
	 *
	 * @return An access token if the enableRefreshTokens setting is false, else a struct with the access and refresh token: { access_token : "", refresh_token : "" }
	 *
	 * @throws InvalidCredentials
	 */
	any function attempt(
		required username,
		required password,
		struct customClaims        = {},
		struct refreshCustomClaims = {}
	){
		// Authenticate via the auth service wired up
		// If it fails an exception is thrown
		var oUser = variables.cbSecurity.getAuthService().authenticate( arguments.username, arguments.password );

		// Store User in ColdBox data bus
		variables.requestService
			.getContext()
			.setPrivateValue( variables.settings.authentication.prcUserVariable, oUser );

		// Create the token(s) and return it
		return fromUser(
			oUser,
			arguments.customClaims,
			arguments.refreshCustomClaims
		);
	}

	/**
	 * Logout a user and invalidate their access token
	 *
	 * @user        
	 * @customClaims
	 */
	function logout(){
		this.invalidate( this.getToken() );
		variables.cbSecurity.getAuthService().logout();
	}

	/**
	 * Shortcut function to our authentication services to check if we are logged in
	 */
	boolean function isLoggedIn(){
		// We try to authenticate because we need the JWT to be validated for the request
		// There are ocassions where the user could have logged out but the token is still active
		// Or the inverse, where there is no more token passed and user still logged in in session.
		try {
			this.authenticate();
		} catch ( any e ) {
			return false;
		}

		return variables.cbSecurity.getAuthService().isLoggedIn();
	}

	/**
	 * Create an access or an access/refresh token(s) according to the passed user object and custom claims.
	 * We are assuming the user is a valid and authenticated user.
	 *
	 * If the setting enableRefreshTokens is true, then we will return a struct of tokens:
	 * <code>{ access_token : "", refresh_token : "" }</code>
	 *
	 * @user                The user to generate the token for, must implement IAuth and IJwtSubject
	 * @customClaims        A struct of custom claims to add to the jwt token if successful.
	 * @refreshCustomClaims A struct of custom claims to add to the refresh token if successful.
	 *
	 * @return An access token if the enableRefreshTokens setting is false, else a struct with the access and refresh token: { access_token : "", refresh_token : "" }
	 */
	any function fromUser(
		required user,
		struct customClaims        = {},
		struct refreshCustomClaims = {}
	){
		// Refresh token and access token
		if ( variables.settings.jwt.enableRefreshTokens ) {
			structAppend(
				arguments.refreshCustomClaims,
				arguments.customClaims,
				false
			);
			return {
				"access_token"  : generateToken( user: arguments.user, customClaims: arguments.customClaims ),
				"refresh_token" : generateToken(
					user        : arguments.user,
					customClaims: arguments.refreshCustomClaims,
					refresh     : true
				)
			};
		}

		// Access token only.
		return generateToken( user: arguments.user, customClaims: arguments.customClaims );
	}

	/**
	 * Authenticates a payload that is passed in or auto-discovered if not passed. This will return the user the payload represents
	 * via the `sub` claim
	 *
	 * @payload The authentication payload to authenticate, by default we auto discover it
	 *
	 * @return User object that implements IAuth and IJwtSubject
	 *
	 * @throws InvalidUser if user is not found
	 */
	function authenticate( payload = getPayload() ){
		// Get the User it represents
		var oUser = variables.cbSecurity
			.getUserService()
			.retrieveUserById( isNull( arguments.payload.sub ) ? "" : arguments.payload.sub );

		// Verify it
		if ( isNull( oUser ) || !len( oUser.getId() ) ) {
			// Announce the invalid user
			variables.interceptorService.announce( "cbSecurity_onJWTInvalidUser", { payload : arguments.payload } );
			throw( message = "The user was not found by the user service", type = "InvalidTokenUser" );
		}

		// Log in the user
		variables.cbSecurity.getAuthService().login( oUser );

		// Store in ColdBox data bus
		variables.requestService
			.getContext()
			.setPrivateValue( variables.settings.authentication.prcUserVariable, oUser );

		// Announce the valid authentication
		variables.interceptorService.announce(
			"cbSecurity_onJWTValidAuthentication",
			{ payload : arguments.payload, user : oUser }
		);

		// Return the user
		return oUser;
	}

	/**
	 * Invalidates the incoming token by removing it from the permanent storage, no key in storage, it's invalid.
	 *
	 * @token The token to invalidate
	 */
	boolean function invalidate( required token ){
		// If not enabled, skip out
		if ( !variables.settings.jwt.tokenStorage.enabled ) {
			return false;
		}

		if ( variables.log.canInfo() ) {
			variables.log.info( "Token invalidation request issued for :#arguments.token#" );
		}

		// Invalidate the token, decode it first and use the jti claim
		var results = getTokenStorage().clear( this.decode( arguments.token ).jti );

		// Announce the token invalidation
		variables.interceptorService.announce( "cbSecurity_onJWTInvalidation", { token : arguments.token } );

		return results;
	}

	/**
	 * Invalidates all tokens in the connected storage provider
	 *
	 * @async Run the clearing asynchronously or not, default is false
	 */
	JwtService function invalidateAll( boolean async = false ){
		// If not enabled, skip out
		if ( !variables.settings.jwt.tokenStorage.enabled ) {
			return false;
		}

		if ( variables.log.canInfo() ) {
			variables.log.info( "Token invalidation request issued for all tokens" );
		}

		// Clear all via storage
		getTokenStorage().clearAll( arguments.async );

		// Announce the token invalidation
		variables.interceptorService.announce( "cbSecurity_onJWTInvalidateAllTokens" );

		if ( variables.log.canInfo() ) {
			variables.log.info( "All tokens cleared via token storage clear all" );
		}

		return this;
	}

	/**
	 * Verifies if the passed in token exists in the storage provider
	 *
	 * @token The token to check
	 */
	boolean function isTokenInStorage( required token ){
		// If not enabled, skip out
		if ( !variables.settings.jwt.tokenStorage.enabled ) {
			return false;
		}
		return getTokenStorage().exists( this.decode( arguments.token ).jti );
	}

	/**
	 * Manually refresh tokens by passing a valid refresh token and returning two new tokens:
	 * <code>{ access_token : "", refresh_token : "" }</code>
	 *
	 * @refreshToken        A refresh token
	 * @customClaims        A struct of custom claims to apply to the new tokens
	 * @refreshCustomClaims A struct of custom claims to add to the refresh token
	 *
	 * @return A struct of { access_token : "", refresh_token : "" }
	 *
	 * @throws RefreshTokensNotActive If the setting enableRefreshTokens is false
	 * @throws TokenExpiredException  If the token has expired or no longer in the storage (invalidated)
	 * @throws TokenInvalidException  If the token doesn't verify decoding
	 * @throws TokenNotFoundException If the token cannot be found in the headers
	 */
	struct function refreshToken(
		token                      = discoverRefreshToken(),
		struct customClaims        = {},
		struct refreshCustomClaims = {}
	){
		if ( !variables.settings.jwt.enableRefreshTokens ) {
			throw(
				type   : "RefreshTokensNotActive",
				message: "You cannot use refresh token methods because this feature has been disabled. Enable it using the `jwt.enableRefreshTokens` setting"
			);
		}

		// Parse and validate token
		var payload = parseToken(
			token         : arguments.token,
			storeInContext: false,
			authenticate  : false
		);

		// Authenticate and make sure the subject is valid
		var oUser = authenticate( payload: payload );

		// Build new tokens according to validated user
		var results = fromUser(
			oUser,
			arguments.customClaims,
			arguments.refreshCustomClaims
		);

		// Invalidate the refresh token: Token Rotation
		invalidate( arguments.token );

		// Return new token set
		return results;
	}

	/************************************************************************************/
	/****************************** PARSING + COLDBOX INTEGRATION METHODS ***************/
	/************************************************************************************/

	/**
	 * Try's to get a jwt token from the authorization header or the custom header
	 * defined in the configuration or passed in by you. If it is a valid token and it decodes we will then
	 * continue to validate the subject it represents.  Once those are satisfied, then it will
	 * store it in the `prc` as `prc.jwt_token` and the payload as `prc.jwt_payload`.
	 *
	 * @token          The token to parse and validate, if not passed we call the discoverToken() method for you.
	 * @storeInContext By default, the token will be stored in the request context
	 * @authenticate   By default, the token will be authenticated, you can disable it and do manual authentication.
	 *
	 * @return The payload for convenience
	 *
	 * @throws TokenExpiredException  If the token has expired or no longer in the storage (invalidated)
	 * @throws TokenInvalidException  If the token doesn't verify decoding
	 * @throws TokenNotFoundException If the token cannot be found in the headers
	 */
	struct function parseToken(
		string token           = discoverToken(),
		boolean storeInContext = true,
		boolean authenticate   = true
	){
		// Did we find an incoming token
		if ( !len( arguments.token ) ) {
			if ( variables.log.canDebug() ) {
				variables.log.debug( "Token empty or not found anywhere (headers, url, form)" );
			}

			throw(
				message = "Token not found in authorization header or the custom header or the request collection or not passed in",
				type    = "TokenNotFoundException"
			);
		}

		// Decode it
		var decodedToken  = decode( arguments.token );
		var decodedClaims = decodedToken.keyArray();

		// Verify the required claims
		var requiredClaims = [];
		requiredClaims
			.append( variables.settings.jwt.requiredClaims, true )
			.append( variables.REQUIRED_CLAIMS, true );
		requiredClaims.each( function( item ){
			if ( !decodedClaims.findNoCase( arguments.item ) ) {
				if ( variables.log.canWarn() ) {
					variables.log.warn(
						"Token is invalid as it does not contain the `#arguments.item#` claim",
						decodedToken
					);
				}

				// Announce the invalid claims
				variables.interceptorService.announce(
					"cbSecurity_onJWTInvalidClaims",
					{ token : arguments.token, payload : decodedToken }
				);

				throw(
					message = "Token is invalid as it does not contain the `#arguments.item#` claim",
					type    = "TokenInvalidException"
				);
			}
		} );

		// Verify Expiration first
		if (
			dateCompare( ( isDate( decodedToken.exp ) ? decodedToken.exp : fromEpoch( decodedToken.exp ) ), now() ) < 0
		) {
			if ( variables.log.canWarn() ) {
				variables.log.warn( "Token rejected, it has expired", decodedToken );
			}

			// Announce the token expiration
			variables.interceptorService.announce(
				"cbSecurity_onJWTExpiration",
				{ token : arguments.token, payload : decodedToken }
			);

			throw( message = "Token has expired", type = "TokenExpiredException" );
		}

		// Verify that this token has not been invalidated in the storage?
		if ( variables.settings.jwt.tokenStorage.enabled && !getTokenStorage().exists( decodedToken.jti ) ) {
			if ( variables.log.canWarn() ) {
				variables.log.warn( "Token rejected, it was not found in token storage", decodedToken );
			}

			// Announce the rejection, token not found in storage
			variables.interceptorService.announce(
				"cbSecurity_onJWTStorageRejection",
				{ token : arguments.token, payload : decodedToken }
			);

			throw(
				message = "Token has expired, not found in storage",
				detail  = "Storage lookup failed",
				type    = "TokenRejectionException"
			);
		}

		// Log
		if ( variables.log.canDebug() ) {
			variables.log.debug(
				"Token is valid, not expired and found in (enabled) storage, inflating to PRC",
				decodedToken
			);
		}

		// Store if enabled
		if ( arguments.storeInContext ) {
			// Store it on the PRC scope values
			variables.requestService
				.getContext()
				.setPrivateValue( "jwt_token", arguments.token )
				.setPrivateValue( "jwt_payload", decodedToken );

			// Announce the valid parsing
			variables.interceptorService.announce(
				"cbSecurity_onJWTValidParsing",
				{ token : arguments.token, payload : decodedToken }
			);
		}

		// Authenticate if enabled
		if ( arguments.authenticate ) {
			// Authenticate the payload, because a token MUST be valid before usage
			this.authenticate( payload: decodedToken );
		}

		// Return it
		return decodedToken;
	}

	/**
	 * Get the stored token from `prc.jwt_token`, if it doesn't exist, it tries to parse it via `parseToken()`,
	 * if not token is set then this will be an empty string.
	 */
	string function getToken(){
		var event = variables.requestService.getContext();

		if ( !event.privateValueExists( "jwt_token" ) ) {
			parseToken();
		}

		return event.getPrivateValue( "jwt_token" );
	}

	/**
	 * Store a manual token in `prc.jwt_token`, and store the decoded version in `prc.jwt_payload`
	 *
	 * @token A custom token to store in the ColdBox event bus
	 */
	function setToken( required token ){
		variables.requestService
			.getContext()
			.setPrivateValue( "jwt_token", arguments.token )
			.setPrivateValue( "jwt_payload", decode( arguments.token ) );

		return this;
	}

	/**
	 * Get the stored token from `prc.jwt_payload`, if it doesn't exist, it tries to parse it via `parseToken()`, if no token is set this will be an empty struct.
	 */
	struct function getPayload(){
		var event = variables.requestService.getContext();

		if ( !event.privateValueExists( "jwt_payload" ) ) {
			parseToken();
		}

		return event.getPrivateValue( "jwt_payload" );
	}

	/**
	 * Get the authenticated user stored on `prc` via the variables.settings.authentication.prcUserVariable setting.
	 * if it doesn't exist, then call parseToken() and try to load it and authenticate it.
	 *
	 * @return The user that implements IAuth and IJwtSubject
	 */
	function getUser(){
		var event = variables.requestService.getContext();

		if ( !event.privateValueExists( variables.settings.authentication.prcUserVariable ) ) {
			parseToken();
		}

		return event.getPrivateValue( variables.settings.authentication.prcUserVariable );
	}

	/************************************************************************************/
	/****************************** RAW JWT Methods *************************************/
	/************************************************************************************/

	/**
	 * Create a jwt token according to the passed in payload.
	 * This method does not store the token in the storage
	 *
	 * @payload The payload to encode
	 */
	string function encode( required struct payload ){
		return variables.jwt.encode(
			arguments.payload,
			variables.settings.jwt.secretKey,
			variables.settings.jwt.algorithm
		);
	}

	/**
	 * Verify an incoming token against our jwt library to check if it is valid token only
	 * No expiration or claim verification
	 *
	 * @token The token to validate
	 */
	boolean function verify( required token ){
		try {
			this.decode( arguments.token );
			return true;
		} catch ( Any e ) {
			return false;
		}
	}

	/**
	 * Decode a jwt token
	 *
	 * @token The token to decode
	 *
	 * @throws TokenInvalidException - When the token cannot be decoded
	 * @throws TokenExpiredException - When the token has expired
	 */
	struct function decode( required token ){
		try {
			return variables.jwt.decode(
				token      = arguments.token,
				key        = variables.settings.jwt.secretKey,
				algorithms = variables.settings.jwt.algorithm,
				claims     = { "iss" : variables.settings.jwt.issuer }
			);
		} catch ( "jwtcfml.ExpiredSignature" e ) {
			if ( variables.log.canWarn() ) {
				variables.log.warn( "Token rejected, it has expired", arguments.token );
			}

			// Announce the token expiration
			variables.interceptorService.announce( "cbSecurity_onJWTExpiration", { token : arguments.token } );

			throw( type = "TokenExpiredException", message = "Token has expired" );
		} catch ( any e ) {
			throw(
				message = "Cannot decode token: #e.message#",
				detail  = e.stackTrace,
				type    = "TokenInvalidException"
			);
		}
	}

	/**
	 * Convert a target local timestamp to epoch
	 *
	 * @target The local timestamp
	 */
	function toEpoch( required target ){
		return dateDiff(
			"s",
			dateConvert( "utc2local", "January 1 1970 00:00" ),
			arguments.target
		);
	}

	/**
	 * Convert an epoch timestamp to local timestamp
	 *
	 * @target The epoch timestamp
	 */
	function fromEpoch( required target ){
		return dateAdd(
			"s",
			arguments.target, // should be in utc
			dateConvert( "utc2local", "January 1 1970 00:00" )
		);
	}

	/**
	 * Get the appropriate token storage provider
	 *
	 * @force If true, it will rebuild the storage using the settings, else it does lazy loading checks
	 *
	 * @return cbsecurity.interfaces.jwt.IJwtStorage
	 */
	function getTokenStorage( boolean force = false ){
		// If loaded, use it! Unless force = true
		if ( !isNull( variables.tokenStorage ) && !arguments.force ) {
			return variables.tokenStorage;
		}

		// Build the appropriate driver
		switch ( variables.settings.jwt.tokenstorage.driver ) {
			case "cachebox": {
				variables.tokenStorage = variables.wirebox.getInstance( "CacheTokenStorage@cbsecurity" );
				break;
			}
			case "db": {
				variables.tokenStorage = variables.wirebox.getInstance( "DBTokenStorage@cbsecurity" );
				break;
			}
			default: {
				variables.tokenStorage = variables.wirebox.getInstance(
					variables.settings.jwt.tokenStorage.driver
				);
				break;
			}
		}

		// Configure the driver
		variables.tokenStorage.configure( variables.settings.jwt.tokenStorage.properties );

		return variables.tokenStorage;
	}

	/**
	 * Generate an access or refresh token bound to the passed user and custom claims.
	 *
	 * @user         The user to generate the token for, must implement IAuth and IJwtSubject
	 * @customClaims A struct of custom claims to add to the jwt token if successful.
	 *
	 * @return An access or refresh token
	 */
	private function generateToken(
		required user,
		struct customClaims = {},
		boolean refresh     = false
	){
		var timestamp = now();
		var payload   = {
			// Issuing authority
			"iss" : variables.settings.jwt.issuer,
			// Token creation time
			"iat" : toEpoch( timestamp ),
			// The subject identifier: user id
			"sub" : arguments.user.getId(),
			// The token expiration according to our settings: access or refresh token expiration
			"exp" : toEpoch(
				dateAdd(
					"n",
					arguments.refresh ? variables.settings.jwt.refreshExpiration : variables.settings.jwt.expiration,
					timestamp
				)
			),
			// The unique identifier of the token
			"jti"   : hash( timestamp & arguments.user.getId() & getTickCount() & rand( "SHA1PRNG" ) ),
			// Get the user scopes for the JWT token
			"scope" : arguments.user.getJwtScopes().toList( " " )
		};

		// Add custom claim if this is a refresh token
		if ( arguments.refresh ) {
			payload[ "cbsecurity_refresh" ] = true;
		}

		// Append user custom claims with override, they take prescedence
		structAppend(
			payload,
			arguments.user.getJwtCustomClaims( payload ),
			true
		);

		// Append incoming custom claims with override, they take prescedence
		structAppend( payload, arguments.customClaims, true );

		for ( var key in payload ) {
			if ( !structKeyExists( payload, key ) || isNull( payload[ key ] ) ) {
				continue;
			}

			if ( isCustomFunction( payload[ key ] ) || isClosure( payload[ key ] ) ) {
				var fn         = payload[ key ];
				payload[ key ] = fn( payload );
			}
		}

		// Create the token for the user
		var jwtToken = this.encode( payload );

		// Store it with the expiration as well if enabled
		if ( variables.settings.jwt.tokenStorage.enabled ) {
			getTokenStorage().set(
				key        = payload.jti,
				token      = jwtToken,
				expiration = dateDiff(
					"n",
					fromEpoch( payload.iat ),
					fromEpoch( payload.exp )
				),
				payload = payload
			);
		}

		// Announce the creation
		variables.interceptorService.announce(
			"cbSecurity_onJWTCreation",
			{
				token   : jwtToken,
				payload : payload,
				user    : arguments.user,
				refresh : arguments.refresh
			}
		);

		return jwtToken;
	}

	/**
	 * Try to discover the jwt token from many incoming resources:
	 * - The custom auth header: x-auth-token
	 * - URL/FORM: x-auth-token
	 * - Authorization Header
	 *
	 * @return The discovered token or an empty string
	 */
	string function discoverToken(){
		var event = variables.requestService.getContext();

		// Discover api token from headers using a custom header or the incoming RC
		var jwtToken = event.getHTTPHeader(
			header       = variables.settings.jwt.customAuthHeader,
			defaultValue = event.getValue( name = variables.settings.jwt.customAuthHeader, defaultValue = "" )
		);

		// If we found it, return it, else try other headers
		if ( jwtToken.len() ) {
			return jwtToken;
		}

		// Authorization Header
		return event
			.getHTTPHeader( header = "Authorization", defaultValue = "" )
			.replaceNoCase( "Bearer", "" )
			.trim();
	}

	/**
	 * Try to discover the jwt refresh token from many incoming resources:
	 * - The custom auth header: x-refresh-token
	 * - URL/FORM: x-refresh-token
	 *
	 * @return The discovered refresh token or an empty string
	 */
	string function discoverRefreshToken(){
		var event = variables.requestService.getContext();

		// Discover api token from headers using a custom header or the incoming RC
		return event.getHTTPHeader(
			header       = variables.settings.jwt.customRefreshHeader,
			defaultValue = event.getValue( name = variables.settings.jwt.customRefreshHeader, defaultValue = "" )
		);
	}

	/**
	 * DEPRECATED: USE JwtAuthValidator@cbsecurity
	 */
	struct function ruleValidator( required rule, required controller ){
		throw(
			type   : "DeprecatedValidator",
			message: "This validator is now deprecated in this version.  Please change it to use `JwtAuthValidator@cbsecurity` in your configuration."
		);
	}

	/**
	 * DEPRECATED: USE JwtAuthValidator@cbsecurity
	 */
	struct function annotationValidator( required securedValue, required controller ){
		throw(
			type   : "DeprecatedValidator",
			message: "This validator is now deprecated in this version.  Please change it to use `JwtAuthValidator@cbsecurity` in your configuration."
		);
	}

}
