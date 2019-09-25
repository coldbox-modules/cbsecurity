/**
 * Copyright since 2016 by Ortus Solutions, Corp
 * www.ortussolutions.com
 * ---
 * This is the JWT Services that will provide you with glorious JWT capabilities.
 * Learn more about Json Web Tokens here: https://jwt.io/
 */
component accessors="true" singleton{

	// DI
	property name="jwt" 				inject="provider:JWTService@jwt";
	property name="wirebox" 			inject="wirebox";
	property name="settings" 			inject="coldbox:moduleSettings:cbSecurity";
	property name="interceptorService" 	inject="coldbox:interceptorService";
	property name="requestService" 		inject="coldbox:requestService";
	property name="log"			 		inject="logbox:logger:{this}";

	/**
	 * The auth service in use
	 */
	property name="authService";

	/**
	 * The user service in use
	 */
	property name="userService";

	/**
	 * The token storage provider
	 */
	property name="tokenStorage";

	// Required Claims
	variables.REQUIRED_CLAIMS = [ "jti", "iss", "iat", "sub", "exp", "scopes" ];

	/**
	 * Constructor
	 */
	function init(){
		return this;
	}

	/**
	 * Runs after DI
	 */
	function onDIComplete(){
		// Verify a few settings just in case
		if ( isNull( variables.settings.jwt.secretKey ) || !len( variables.settings.jwt.secretKey ) ){
			throw(
				message = "The JWT secret key cannot be empty, please fill this out in your `config/ColdBox.cfc` under your cbsecurity settings",
				detail 	= "cbsecurity.jwt.secretKey",
				type 	= "InvalidSecretKey"
			)
		}
	}

	/************************************************************************************/
	/****************************** TOKEN CREATION METHODS ******************************/
	/************************************************************************************/

	/**
	 * Attempt to authenticate a user with the auth service and if succesful return a jwt token
	 * using the information in the authenticated user.
	 *
	 * @username The username to use
	 * @password The password to use
	 * @customClaims A struct of custom claims to add to the jwt token if successful.
	 *
	 * @throws InvalidCredentials
	 */
	string function attempt( required username, required password, struct customClaims={} ){
		var auth = getAuthService();

		if( auth.authenticate( arguments.username, arguments.password ) ){
			// Create it
			return fromUser( auth.getUser(), arguments.customClaims );
		} else {
			// Can't do anything if the authenticate is false.
			throw(
				message = "The credentials are invalid!",
				type 	= "InvalidCredentials"
			);
		}
	}

	/**
	 * Logout a user and invalidate their token
	 *
	 * @user
	 * @customClaims
	 */
	function logout(){
		invalidate( this.getToken() );
		getAuthService().logout();
	}

	/**
	 * Shortcut function to our authentication services to check if we are logged in
	 */
	boolean function isLoggedIn(){
		return getAuthService().isLoggedIn();
	}

	/**
	 * Create a token according to the passed user object and custom claims.
	 * We are assuming the user is a valid and authenticated user.
	 *
	 * @user The user to generate the token for, must implement IAuth and IJwtSubject
	 * @customClaims A struct of custom claims to add to the jwt token if successful.
	 */
	string function fromUser( required user, struct customClaims={} ){
		var event 		= variables.requestService.getContext();
		var timestamp 	= now();
		var payload 	= {
			// Issuing authority
			"iss" 		: event.getHTMLBaseURL(),
			// Token creation
			"iat" 		: toEpoch( timestamp ),
			// The subject identifier
			"sub" 		: arguments.user.getId(),
			// The token expiration
			"exp" 		: toEpoch( dateAdd( "n", variables.settings.jwt.expiration, timestamp ) ),
			// The unique identifier of the token
			"jti" 		: hash( timestamp & arguments.user.getId() ),
			// Get the user scopes for the JWT token
			"scopes" 	: arguments.user.getJwtScopes()
		};

		// Append user custom claims with override, they take prescedence
		structAppend( payload, arguments.user.getJwtCustomClaims(), true );

		// Append incoming custom claims with override, they take prescedence
		structAppend( payload, arguments.customClaims, true );

		// Create the token for the user
		var jwtToken = this.encode(	payload );

		// Store it with the expiration as well if enabled
		if( variables.settings.jwt.tokenStorage.enabled ){
			getTokenStorage().set(
				key 		= payload.jti,
				token 		= jwtToken,
				expiration 	= variables.settings.jwt.expiration,
				payload		= payload
			);
		}

		// Announce the creation
		variables.interceptorService.processState( "cbSecurity_onJWTCreation", {
			token 	: jwtToken,
			payload : payload,
			user 	: arguments.user
		} );

		// Return it
		return jwtToken;
	}

	/**
	 * Calls the auth service using the parsed token or optional passed token, to get the user by subject claim else throw an exception
	 *
	 * @returns User object that implements IAuth and IJwtSubject
	 * @throws InvalidUser if user is not found
	 */
	function authenticate(){
		// Get the User it represents
		var oUser = getUserService().retrieveUserById( getPayload().sub );

		// Verify it
		if( isNull( oUser ) || !len( oUser.getId() ) ){
			// Announce the creation
			variables.interceptorService.processState( "cbSecurity_onJWTInvalidUser", {
				token 	: this.getToken(),
				payload	: this.getPayload()
			} );

			throw(
				message = "The user (#getPayload().sub#) was not found by the user service",
				type 	= "InvalidTokenUser"
			);
		}

		// Log in the user
		getAuthService().login( oUser );

		// Store in ColdBox data bus
		variables.requestService
			.getContext()
			.setPrivateValue( variables.settings.prcUserVariable, oUser );

		// Announce the creation
		variables.interceptorService.processState( "cbSecurity_onJWTValidAuthentication", {
			token 	: this.getToken(),
			payload	: this.getPayload(),
			user 	: oUser
		} );

		// Return the user
		return oUser;
	}

	/**
	 * Invalidates the incoming token by removing it from the permanent storage, no key in storage, it's invalid.
	 *
	 * @token The token to invalidate
	 */
	boolean function invalidate( required token ){
		if( variables.log.canInfo() ){
			variables.log.info( "Token invalidation request issued for :#arguments.token#" );
		}

		var results = getTokenStorage().clear( arguments.token );

		// Announce the creation
		variables.interceptorService.processState( "cbSecurity_onJWTInvalidation", {
			token 	: arguments.token
		} );

		return results;
	}

	/************************************************************************************/
	/****************************** PARSING + COLDBOX INTEGRATION METHODS ***************/
	/************************************************************************************/

	/**
	 * Try's to get a jwt token from the authorization header or the custom header
	 * defined in the configuration. If it is a valid token and it decodes we will then
	 * continue to validat the subject it represents.  Once those are satisfied, then it will
	 * store it in the `prc` as `prc.jwt_token` and the payload as `prc.jwt_payload`.
	 *
	 * @throws TokenExpiredException If the token has expired or no longer in the storage (invalidated)
	 * @throws TokenInvalidException If the token doesn't verify decoding
	 * @throws TokenNotFoundException If the token cannot be found in the headers
	 *
	 * @returns The payload for convenience
	 */
	struct function parseToken(){
		var jwtToken = discoverToken();

		// Did we find an incoming token
		if( !len( jwtToken ) ){
			if( variables.log.canDebug() ){
				variables.log.debug( "Token not found anywhere" );
			}

			throw(
				message = "Token not found in authorization header or the custom header or the request collection",
				type 	= "TokenNotFoundException"
			);
		}

		// Decode it
		var decodedToken 	= decode( jwtToken );
		var decodedClaims 	= decodedToken.keyArray();

		// Verify the required claims
		var requiredClaims = [];
		requiredClaims
			.append( variables.settings.jwt.requiredClaims, true )
			.append( variables.REQUIRED_CLAIMS, true );
		requiredClaims
			.each( function( item ){
				if( !decodedClaims.findNoCase( arguments.item ) ){

					if( variables.log.canWarn() ){
						variables.log.warn( "Token is invalid as it does not contain the `#arguments.item#` claim", decodedToken );
					}

					// Announce the creation
					variables.interceptorService.processState( "cbSecurity_onJWTInvalidClaims", {
						token 	: jwtToken,
						payload	: decodedToken
					} );

					throw(
						message = "Token is invalid as it does not contain the `#arguments.item#` claim",
						type 	= "TokenInvalidException"
					);
				}
			} );

		// Verify Expiration first
		if( dateCompare( fromEpoch( decodedToken.exp ), now() ) < 0 ){

			if( variables.log.canWarn() ){
				variables.log.warn( "Token rejected, it has expired", decodedToken );
			}

			// Announce the creation
			variables.interceptorService.processState( "cbSecurity_onJWTExpiration", {
				token 	: jwtToken,
				payload	: decodedToken
			} );

			throw(
				message = "Token has expired",
				type 	= "TokenExpiredException"
			);
		}

		// Verify that this token has not been invalidated in the storage?
		if( !getTokenStorage().exists( decodedToken.jti ) ){
			if( variables.log.canWarn() ){
				variables.log.warn( "Token rejected, it was not found in token storage", decodedToken );
			}

			// Announce the creation
			variables.interceptorService.processState( "cbSecurity_onJWTStorageRejection", {
				token 	: jwtToken,
				payload	: decodedToken
			} );

			throw(
				message = "Token has expired, not found in storage",
				detail 	= "Storage lookup failed",
				type 	= "TokenRejectionException"
			);
		}

		// Log
		if( variables.log.canDebug() ){
			variables.log.debug( "Token is valid, not expired and found in storage, inflating to PRC", decodedToken );
		}

		// Store it
		variables.requestService
			.getContext()
			.setPrivateValue( "jwt_token", jwtToken )
			.setPrivateValue( "jwt_payload", decodedToken );

		// Announce the creation
		variables.interceptorService.processState( "cbSecurity_onJWTValidParsing", {
			token 	: jwtToken,
			payload	: decodedToken
		} );

		// Authenticate the payload
		authenticate();

		// Return it
		return decodedToken;
	}

	/**
	 * Get the stored token from `prc.jwt_token`, if it doesn't exist, it tries to parse it via `parseToken()`,
	 * if not token is set then this will be an empty string.
	 */
	string function getToken(){
		var event = variables.requestService.getContext();

		if( !event.privateValueExists( "jwt_token" ) ){
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

		if( !event.privateValueExists( "jwt_payload" ) ){
			parseToken();
		}

		return event.getPrivateValue( "jwt_payload" );
	}

	/**
	 * Get the authenticated user stored on `prc` via the variables.settings.prcUserVariable setting.
	 * if it doesn't exist, then call parseToken() and try to load it and authenticate it.
	 *
	 * @return The user that implements IAuth and IJwtSubject
	 */
	function getUser(){
		var event = variables.requestService.getContext();

		if( !event.privateValueExists( variables.settings.prcUserVariable ) ){
			parseToken();
		}

		return event.getPrivateValue( variables.settings.prcUserVariable );
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
	 * Verify an incoming token against our jwt library to check if it is valid.
	 *
	 * @token The token to validate
	 */
	boolean function verify( required token ){
		return variables.jwt.verify(
			arguments.token,
			variables.settings.jwt.secretKey,
			variables.settings.jwt.algorithm
		);
	}

	/**
	 * Decode a jwt token
	 *
	 * @token The token to decode
	 *
	 * @throws InvalidToken
	 */
	struct function decode( required token ){
		try{
			return variables.jwt.decode(
				arguments.token,
				variables.settings.jwt.secretKey,
				variables.settings.jwt.algorithm
			);
		} catch( any e ){
			throw(
				message = "Cannot decode token: #e.message#",
				detail 	= e.stackTrace,
				type = "TokenInvalidException"
			);
		}
	}

	/************************************************************************************/
	/****************************** VALIDATORS ******************************************/
	/************************************************************************************/


	/**
	 * This function is called once an incoming event matches a security rule.
	 * You will receive the security rule that matched and an instance of the
	 * ColdBox controller.
	 *
	 * allow : True, user can continue access, false, invalid access actions will ensue
	 * type : Is the issue an authentication or an authorization issue.
	 *
	 * @return { allow:boolean, type:authentication|authorization }
	 */
	struct function ruleValidator( required rule, required controller ){
		return validateSecurity( arguments.rule.roles );
	}

	/**
	 * This function is called once access to a handler/action is detected.
	 * You will receive the secured annotation value and an instance of the ColdBox Controller
	 *
	 * You must return a struct with two keys:
	 * - allow:boolean True, user can continue access, false, invalid access actions will ensue
	 * - type:string(authentication|authorization) The type of block that ocurred.  Either an authentication or an authorization issue.
	 *
	 * @return { allow:boolean, type:string(authentication|authorization) }
	 */
	struct function annotationValidator( required securedValue, required controller ){
		return validateSecurity( arguments.securedValue );
	}

	/**
	 * Convert a target local timestamp to epoch
	 *
	 * @target The local timestamp
	 */
	function toEpoch( required target ){
		return dateDiff(
			's',
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
		return DateAdd(
			"s",
			arguments.target, // should be in utc
			dateConvert( "utc2local", "January 1 1970 00:00" )
		);
	}

	/**
	 * Get the appropriate token storage
	 */
	function getTokenStorage(){
		// If loaded, use it!
		if( !isNull( variables.tokenStorage ) ){
			return variables.tokenStorage;
		}

		// Build the appropriate driver
		switch( variables.settings.jwt.tokenstorage.driver ){
			case "cachebox" : {
				variables.tokenStorage = variables.wirebox.getInstance( "CacheTokenStorage@cbsecurity" );
				break;
			}
			case "db" : {
				variables.tokenStorage = variables.wirebox.getInstance( "DBTokenStorage@cbsecurity" );
				break;
			}
			default : {
				variables.tokenStorage = variables.wirebox.getInstance( variables.settings.jwt.tokenStorage.driver );
				break;
			}
		}

		// Configure the driver
		variables.tokenStorage.configure( variables.settings.jwt.tokenStorage.properties );

		return variables.tokenStorage;
	}

	/**
	 * Get the user service defined in the settings
	 */
	any function getUserService() {
		// If loaded, use it!
		if( !isNull( variables.userService ) ){
			return variables.userService;
		}

		// Check and Load Baby!
        if ( ! len( variables.settings.userService ) ) {
			throw(
				message	= "No [userService] provided in the settings.  Please set in `config/ColdBox.cfc` under `moduleSettings.cbsecurity.userService`.",
				type 	= "IncompleteConfiguration"
			);
        }

		variables.userService = variables.wirebox.getInstance( variables.settings.userService );

        return variables.userService;
	}

	/**
	 * Get the authentication service defined in the settings
	 */
	any function getAuthService() {
		// If loaded, use it!
		if( !isNull( variables.authService ) ){
			return variables.authService;
		}

		// Check and Load Baby!
        if ( ! len( variables.settings.authenticationService ) ) {
			throw(
				message	= "No [authService] provided in the settings.  Please set in `config/ColdBox.cfc` under `moduleSettings.cbsecurity.authenticationService`.",
				type 	= "IncompleteConfiguration"
			);
        }

		variables.authService = variables.wirebox.getInstance( variables.settings.authenticationService );

        return variables.authService;
    }

	/****************************** PRIVATE ******************************/

	/**
	 * Try to discover the jwt token from many incoming resources
	 */
	private string function discoverToken(){
		var event = variables.requestService.getContext();

		// Discover api token from headers using a custom header or the incoming RC
		var jwtToken = event.getHTTPHeader(
			header 			= variables.settings.jwt.customAuthHeader,
			defaultValue	= event.getValue( name=variables.settings.jwt.customAuthHeader, defaultValue="" )
		);

		// If we found it, return it, else try other headers
		if( jwtToken.len() ){
			return jwtToken;
		}

		// Authorization Header
		return event.getHTTPHeader(
				header 			= 'Authorization',
				defaultValue	= ""
			)
			.replaceNoCase( "Bearer", "" )
			.trim();
	}


	/**
	 * Validate Security for the jwt token
	 *
	 * @permissions The permissions we want to validate in the scopes
	 */
	private function validateSecurity( required permissions ){
		var results = { "allow" : false, "type" : "authentication", "messages" : "" };

		try{
			// Try to get the payload from the jwt token, if we have exceptions, we have failed :(
			var payload = getPayload();
		} catch( Any e ){
			results.messages = e.type & ":" & e.message;
			return results;
		}

		// Are we logged in?
		if( getAuthService().isLoggedIn() ){

			// Do we have any permissions to validate?
			if( listLen( arguments.permissions ) ){
				// Check if the user has the right permissions?
				results.allow = (
					tokenHasScopes( arguments.permissions, payload.scopes )
					||
					getAuthService().getUser().hasPermission( arguments.permissions )
				);
				results.type = "authorization";
			} else {
				// We are satisfied!
				results.allow = true;
			}
		}

		return results;
	}

	/**
	 * Verify if the jwt token has the appropriate scopes
	 */
	private function tokenHasScopes( required permission, required scopes ){
		if( isSimpleValue( arguments.permission) ){
			arguments.permission = listToArray( arguments.permission );
		}

		return arguments.permission
			.filter( function( item ){
				return ( scopes.findNoCase( item ) );
			} )
			.len();
	}

}