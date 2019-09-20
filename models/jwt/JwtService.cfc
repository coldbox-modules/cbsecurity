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

	// Properties

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
	 * Create a token according to the passed user object and custom claims.
	 * We are assuming the user is a valid and authenticated user.
	 *
	 * @user The user to generate the token for, must implement IAuth and IJwtSubject
	 * @customClaims A struct of custom claims to add to the jwt token if successful.
	 */
	string function fromUser( required user, struct customClaims={} ){
		var event 		= variables.requestService.getRequestContext();
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
			"scopes" 	: arguments.user.getScopes()
		};

		// Append user custom claims with override, they take prescedence
		structAppend( payload, arguments.user.getJwtCustomClaims(), true );

		// Append incoming custom claims with override, they take prescedence
		structAppend( payload, arguments.customClaims, true );

		// Create the token
		var jwtToken = jwt.encode(
			payload,
			variables.settings.jwt.secretKey,
			variables.settings.jwt.algorithm
		);

		// Store it with the expiration as well if enabled
		if( variables.settings.jwt.tokenStorage.enabled ){
			getTokenStorage().set( payload.jti, jwtToken, variables.settings.jwt.expiration );
		}

		// Return it
		return jwtToken;
	}

	/**
	 * Calls the auth service using the parsed token or optional passed token, to get the user by subject claim else throw an exception
	 *
	 * @token Optional token to use, by default we use the parsed token.
	 *
	 * @returns User object that implements IAuth and IJwtSubject
	 * @throws InvalidUser if user is not found
	 */
	function authenticate(){
		var oUser = getUserService().get( getPayload().sub );

		// Verify it
		if( isNull( oUser ) || !len( oUser.getId() ) ){
			throw(
				message = "The user (#getPayload().sub#) was not found by the user service",
				type 	= "InvalidUser"
			);
		}

		// Log in the user
		getAuthService().login( oUser );

		// Store in ColdBox data bus
		variables.requestService
			.getRequestContext()
			.setPrivateValue( variables.settings.prcUserVariable, oUser )

		// Return the user
		return oUser;
	}

	/**
	 * Invalidates the incoming token by removing it from the permanent storage, no key in storage, it's invalid.
	 *
	 * @token The token to invalidate
	 */
	boolean function invalidate( required token ){
		if( getTokenStorage().exists( arguments.token ) ){
			getTokenStorage().clear( arguments.token );
			return true;
		}

		return false;
	}

	/************************************************************************************/
	/****************************** PARSING + COLDBOX INTEGRATION METHODS ***************/
	/************************************************************************************/

	/**
	 * Try's to get a jwt token from the authorization header or the custom header
	 * defined in the configuration. If it is a valid token and it decodes, then it will
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
					throw(
						message = "Token is invalid as it does not contain the `#arguments.item#` claim",
						type 	= "TokenInvalidException"
					);
				}
			} );

		// Verify Expiration first
		if( dateCompare( fromEpoch( decodedToken.exp ), now() ) < 0 ){
			throw(
				message = "Token has expired",
				type 	= "TokenExpiredException"
			);
		}

		// Verify that this token has not been invalidated in the storage?
		if( getTokenStorage().exists( jwtToken.jti ) ){
			throw(
				message = "Token has expired, not found in storage",
				detail 	= "Storage lookup failed",
				type 	= "TokenExpiredException"
			);
		}

		// Store it
		variables.requestService
			.getRequestContext()
			.setPrivateValue( "jwt_token", jwtToken )
			.setPrivateValue( "jwt_payload", decodedToken );

		// Return it
		return decodedToken;
	}

	/**
	 * Get the stored token from `prc.jwt_token`, if it doesn't exist, it tries to parse it via `parseToken()`,
	 * if not token is set then this will be an empty string.
	 */
	string function getToken(){
		var event = variables.requestService.getRequestContext();

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
			.getRequestContext()
			.setPrivateValue( "jwt_token", arguments.token )
			.setPrivateValue( "jwt_payload", decode( arguments.token ) );

		return this;
	}

	/**
	 * Get the stored token from `prc.jwt_payload`, if it doesn't exist, it tries to parse it via `parseToken()`, if no token is set this will be an empty struct.
	 */
	struct function getPayload(){
		var event = variables.requestService.getRequestContext();

		if( !event.privateValueExists( "jwt_payload" ) ){
			parseToken();
		}

		return event.getPrivateValue( "jwt_payload" );
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
	string function decode( required token ){
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
			},
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
        if ( ! len( variables.settings.authService ) ) {
			throw(
				message	= "No [authService] provided in the settings.  Please set in `config/ColdBox.cfc` under `moduleSettings.cbsecurity.authenticationService`.",
				type 	= "IncompleteConfiguration"
			);
        }

		variables.authService = variables.wirebox.getInstance( variables.settings.authService );

        return variables.authService;
    }

	/****************************** PRIVATE ******************************/

	/**
	 * Try to discover the jwt token from many incoming resources
	 */
	private string function discoverToken(){
		var event = variables.requestService.getRequestContext();

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
	 * Validate Security
	 *
	 * @roles
	 */
	private function validateSecurity( required roles ){
		var results = { "allow" : false, "type" : "authentication" };

		// Are we logged in?
		if( isUserLoggedIn() ){

			// Do we have any roles?
			if( listLen( arguments.roles ) ){
				results.allow 	= isUserInAnyRole( arguments.roles );
				results.type 	= "authorization";
			} else {
				// We are satisfied!
				results.allow.true;
			}
		}

		return results;
	}

}