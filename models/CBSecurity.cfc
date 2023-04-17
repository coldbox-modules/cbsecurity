/**
 * Copyright since 2016 by Ortus Solutions, Corp
 * www.ortussolutions.com
 * ---
 * This service is in charge of offering security capabilties to your ColdBox applications
 *
 * It can be injected by using the `@cbSecurity` annotation
 *
 * <pre>
 * property name="cbSecurity" inject="@cbsecurity";
 * </pre>
 *
 * Or you can use the `cbSecure()` mixin
 *
 * <pre>
 * cbsecure().secure();
 * </pre>
 */
component threadsafe singleton accessors="true" {

	/*********************************************************************************************/
	/** DI **/
	/*********************************************************************************************/

	property name="settings"       inject="coldbox:moduleSettings:cbsecurity";
	property name="log"            inject="logbox:logger:{this}";
	property name="wirebox"        inject="wirebox";
	property name="async"          inject="coldbox:asyncManager";
	property name="moduleSettings" inject="coldbox:setting:modules";
	property name="DBLogger"       inject="DBLogger@cbsecurity";

	/*********************************************************************************************/
	/** PROPERTIES **/
	/*********************************************************************************************/

	/**
	 * The auth service in use according to the configuration file
	 */
	property name="authService";

	/**
	 * The user service in use according to the configuration file
	 */
	property name="userService";

	/*********************************************************************************************/
	/** Static Vars **/
	/*********************************************************************************************/

	variables.DEFAULT_ERROR_MESSAGE = "Not authorized!";
	variables.DEFAULT_SETTINGS      = {
		authentication : {
			// The WireBox ID of the authentication service to use which must adhere to the cbsecurity.interfaces.IAuthService interface.
			"provider"        : "authenticationService@cbauth",
			// WireBox ID of the user service to use when leveraging user authentication
			"userService"     : "",
			// The name of the variable to use to store an authenticated user in prc scope on all incoming authenticated requests
			"prcUserVariable" : "oCurrentUser"
		},
		csrf : {
			// By default we load up an interceptor that verifies all non-GET incoming requests against the token validations
			enableAutoVerifier     : false,
			// A list of events to exclude from csrf verification, regex allowed: e.g. stripe\..*
			verifyExcludes         : [],
			// By default, all csrf tokens have a life-span of 30 minutes. After 30 minutes, they expire and we aut-generate new ones.
			// If you do not want expiring tokens, then set this value to 0
			rotationTimeout        : 30,
			// Enable the /cbcsrf/generate endpoint to generate cbcsrf tokens for secured users.
			enableEndpoint         : false,
			// The WireBox mapping to use for the CacheStorage
			cacheStorage           : "CacheStorage@cbstorages",
			// Enable/Disable the cbAuth login/logout listener in order to rotate keys
			enableAuthTokenRotator : true
		},
		firewall : {
			// Auto load the global security firewall automatically, else you can load it a-la-carte via the `Security` interceptor
			"autoLoadFirewall"            : true,
			// The validator is an object that will validate the firewall rules and annotations and provide feedback on either authentication or authorization issues.
			"validator"                   : "AuthValidator@cbsecurity",
			// Activate handler/action based annotation security
			"handlerAnnotationSecurity"   : true,
			// The global invalid authentication event or URI or URL to go if an invalid authentication occurs
			"invalidAuthenticationEvent"  : "",
			// Default Auhtentication Action: override or block or redirect when a user has not logged in
			"defaultAuthenticationAction" : "redirect",
			// The global invalid authorization event or URI or URL to go if an invalid authorization occurs
			"invalidAuthorizationEvent"   : "",
			// Default Authorization Action: override or redirect when a user does not have enough permissions to access something
			"defaultAuthorizationAction"  : "redirect",
			// Firewall Rules
			"rules"                       : {
				// Use regular expression matching on the rule match types
				"useRegex" : true,
				// Force SSL for all relocations
				"useSSL"   : false,
				// A collection of default name-value pairs to add to ALL rules
				// This way you can add global roles, permissions, redirects, etc
				"defaults" : {},
				// You can store all your rules in this inline array
				"inline"   : [],
				// If you don't store the rules inline, then you can use a provider to load the rules
				// The source can be a json file, an xml file, model, db
				// Each provider can have it's appropriate properties as well. Please see the documentation for each provider.
				"provider" : { "source" : "", "properties" : {} }
			},
			"logs" : {
				"enabled"    : false,
				"dsn"        : "",
				"schema"     : "",
				"table"      : "cbsecurity_logs",
				"autoCreate" : true
			}
		},
		visualizer : {
			"enabled"      : false,
			"secured"      : false,
			"securityRule" : {}
		},
		securityHeaders : { "enabled" : true },
		securityModules : {}
	};

	/**
	 * Constructor
	 */
	function init(){
		return this;
	}

	function onDIComplete(){
		// Default level-1 settings
		variables.settings.append( variables.DEFAULT_SETTINGS, false );
		// Default level-2 settings
		variables.DEFAULT_SETTINGS.each( function( key, value ){
			variables.settings[ key ].append( value, false );
		} );
		// Default level-3 settings
		if ( isStruct( variables.settings.firewall.rules ) ) {
			variables.settings.firewall.rules.append( variables.DEFAULT_SETTINGS.firewall.rules, false );
		}
		if ( isStruct( variables.settings.firewall.logs ) ) {
			variables.settings.firewall.logs.append( variables.DEFAULT_SETTINGS.firewall.logs, false );
		}

		// Try to discover user service default for cbauth
		if (
			variables.settings.authentication.provider.findNoCase( "@cbauth" ) &&
			!len( variables.settings.authentication.userService ) && len(
				variables.moduleSettings.cbauth.settings.userServiceClass
			)
		) {
			variables.settings.authentication.userService = variables.moduleSettings.cbauth.settings.userServiceClass;
			log.info(
				"+ cbAuth detected and no UserService detected -> User Service set to cbAuth's UserServiceClass"
			);
		}

		// User service default if basic auth is selected
		if (
			!len( variables.settings.authentication.userService ) && variables.settings.firewall.validator == "BasicAuthValidator@cbsecurity"
		) {
			variables.settings.authentication.userService = "BasicAuthUserService@cbsecurity";
			log.info( "+ Basic Auth Validator Detected -> User Service set to BasicAuthUserService" );
		}

		// cbcsrf settings incorporation
		variables.moduleSettings.cbcsrf.settings.append( variables.settings.csrf, false );
		// DBLogger Configuration
		variables.dbLogger.configure();
		// Log it
		log.info( "√ CBSecurity Services started and configured." );
	}

	/**
	 * Get the default rule settings structure
	 */
	struct function getDefaultRuleSettings(){
		return variables.DEFAULT_SETTINGS.firewall.rules;
	}

	/**
	 * Get the user service object defined accordingly in the settings
	 *
	 * @return cbsecurity.interfaces.IUserService
	 *
	 * @throws IncompleteConfiguration
	 */
	any function getUserService(){
		// If loaded, use it!
		if ( !isNull( variables.userService ) ) {
			return variables.userService;
		}

		// Check and Load Baby!
		if ( !len( variables.settings.authentication.userService ) ) {
			throw(
				message = "No [userService] provided in the settings.  Please set it in the `config/ColdBox.cfc` under `moduleSettings.cbsecurity.userService`.",
				type    = "IncompleteConfiguration"
			);
		}

		variables.userService = variables.wirebox.getInstance( variables.settings.authentication.userService );

		return variables.userService;
	}

	/**
	 * Get the authentication service defined accordingly in the settings
	 *
	 * @return cbsecurity.interfaces.IAuthService
	 *
	 * @throws IncompleteConfiguration
	 */
	any function getAuthService(){
		// If loaded, use it!
		if ( !isNull( variables.authService ) ) {
			return variables.authService;
		}

		// Check and Load Baby!
		if ( !len( variables.settings.authentication.provider ) ) {
			throw(
				message = "No [authService] provided in the settings.  Please set in `config/ColdBox.cfc` under `moduleSettings.cbsecurity.authentication.provider`.",
				type    = "IncompleteConfiguration"
			);
		}

		variables.authService = variables.wirebox.getInstance( variables.settings.authentication.provider );

		return variables.authService;
	}

	/**
	 * Get the authenticated user
	 *
	 * Change to delegates on CB7
	 *
	 * @return User that implements IAuthUser
	 *
	 * @throws NoUserLoggedIn : If the user is not logged in
	 */
	any function getUser(){
		return getAuthService().getUser();
	}

	/**
	 * Verifies if a user is logged in
	 */
	boolean function isLoggedIn(){
		return getAuthService().isLoggedIn();
	}

	/**
	 * Verifies if a user is NOT logged in
	 */
	boolean function guest(){
		return !getAuthService().isLoggedIn();
	}

	/**
	 * Login Facade
	 *
	 * @username The username to log in with
	 * @password The password to log in with
	 *
	 * @return User : The logged in user object
	 *
	 * @throws InvalidCredentials
	 */
	any function authenticate( required username, required password ){
		return getAuthService().authenticate( argumentCollection = arguments );
	}

	/**
	 * Logout Facade
	 */
	void function logout(){
		getAuthService().logout();
	}

	/***************************************************************/
	/* Verification Methods
	/***************************************************************/

	/**
	 * Verify if the incoming permissions exist in the currently authenticated user.
	 * All permissions are Or'ed together
	 *
	 * @permissions One, a list or an array of permissions
	 *
	 * @throws NoUserLoggedIn
	 */
	boolean function has( required permissions ){
		var oUser = getAuthService().getUser();

		return arrayWrap( arguments.permissions )
			.filter( function( item ){
				return oUser.hasPermission( arguments.item );
			} )
			.len() > 0;
	}

	/**
	 * Verify that ALL the permissions passed must exist within the authenticated user
	 *
	 * @permissions One, a list or an array of permissions
	 *
	 * @throws NoUserLoggedIn
	 */
	boolean function all( required permissions ){
		var oUser  = getAuthService().getUser();
		var aPerms = arrayWrap( arguments.permissions );

		return aPerms
			.filter( function( item ){
				return oUser.hasPermission( arguments.item );
			} )
			.len() == aPerms.len();
	}

	/**
	 * Verify that NONE of the permissions passed must exist within the authenticated user
	 *
	 * @permissions One, a list or an array of permissions
	 *
	 * @throws NoUserLoggedIn
	 */
	boolean function none( required permissions ){
		var oUser = getAuthService().getUser();

		return arrayWrap( arguments.permissions )
			.filter( function( item ){
				return oUser.hasPermission( arguments.item );
			} )
			.len() == 0;
	}

	/**
	 * Verify that the passed in user object must be the same as the authenticated user
	 * Equality is done by evaluating the `getid()` method on both objects.
	 *
	 * @user The user to test for equality
	 *
	 * @throws NoUserLoggedIn
	 */
	boolean function sameUser( required user ){
		return ( arguments.user.getId() == getAuthService().getUser().getId() );
	}

	/***************************************************************/
	/* Blocking Methods
	/***************************************************************/

	/**
	 * Verifies if the currently logged in user has any of the passed permissions.
	 *
	 * @permissions One, a list or an array of permissions
	 * @message     The error message to throw in the exception
	 *
	 * @return CBSecurity
	 *
	 * @throws NotAuthorized
	 */
	CBSecurity function secure( required permissions, message = variables.DEFAULT_ERROR_MESSAGE ){
		if ( !has( arguments.permissions ) ) {
			throw( type = "NotAuthorized", message = arguments.message );
		}
		return this;
	}

	/**
	 * Verifies if the currently logged in user has ALL of the passed permissions.
	 *
	 * @permissions One, a list or an array of permissions
	 * @message     The error message to throw in the exception
	 *
	 * @return CBSecurity
	 *
	 * @throws NotAuthorized
	 */
	CBSecurity function secureAll( required permissions, message = variables.DEFAULT_ERROR_MESSAGE ){
		if ( !all( arguments.permissions ) ) {
			throw( type = "NotAuthorized", message = arguments.message );
		}
		return this;
	}

	/**
	 * Verifies if the currently logged in user has NONE of the passed permissions.
	 *
	 * @permissions One, a list or an array of permissions
	 * @message     The error message to throw in the exception
	 *
	 * @return CBSecurity
	 *
	 * @throws NotAuthorized
	 */
	CBSecurity function secureNone( required permissions, message = variables.DEFAULT_ERROR_MESSAGE ){
		if ( !none( arguments.permissions ) ) {
			throw( type = "NotAuthorized", message = arguments.message );
		}
		return this;
	}

	/**
	 * Verifies the passed in context closure/lambda/udf to a boolean expression.
	 * If the context is true, then the exception is thrown. The context must be false in order to pass.
	 *
	 * The context udf/closure/lambda must adhere to the following signature
	 *
	 * <pre>
	 * function( user ){}
	 * ( user ) => {}
	 * </pre>
	 *
	 * It receives the currently logged in user
	 *
	 * @context A closure/lambda/udf that returns boolean, or a boolean expression
	 * @message The error message to throw in the exception
	 *
	 * @return CBSecurity
	 *
	 * @throws NotAuthorized
	 */
	CBSecurity function secureWhen( required context, message = variables.DEFAULT_ERROR_MESSAGE ){
		var results = arguments.context;
		// Check if udf/lambda
		if ( isCustomFunction( arguments.context ) || isClosure( arguments.context ) ) {
			results = arguments.context( getAuthService().getUser() );
		}
		if ( results ) {
			throw( type = "NotAuthorized", message = arguments.message );
		}
		return this;
	}

	/**
	 * Verifies that the passed in user object must be the same as the authenticated user.
	 * Equality is done by evaluating the `getid()` method on both objects.
	 * If the equality check fails, a `NotAuthorized` exception is thrown.
	 *
	 * @user    The user to test for equality
	 * @message The error message to throw in the exception
	 *
	 * @throws NoUserLoggedIn
	 * @throws NotAuthorized 
	 */
	CBSecurity function secureSameUser( required user, message = variables.DEFAULT_ERROR_MESSAGE ){
		if ( !sameUser( arguments.user ) ) {
			throw( type = "NotAuthorized", message = arguments.message );
		}
		return this;
	}

	/**
	 * Alias proxy if somebody is coming from cbguard, proxies to the secure() method
	 */
	function guard(){
		return secure( argumentCollection = arguments );
	}

	/***************************************************************/
	/* Action Context Methods
	/***************************************************************/

	/**
	 * This method will verify that any permissions must exist in the currently logged in user.
	 *
	 * - If the result is true, then it will execute the success closure/lambda or udf.
	 * - If the restul is false, then it will execute the fail closure/lambda or udf
	 *
	 * The success or fail closures/lambdas/udfs must match the following signature
	 *
	 * <pre>
	 * function( user, permissions ){}
	 * ( user, permissions ) => {}
	 * </pre>
	 *
	 * They receive the currently logged in user and the permissions that where evaluated
	 *
	 * @permissions One, a list, an array of permissions or boolean evaluation
	 * @success     The closure/lambda/udf that executes if the context passes
	 * @fail        The closure/lambda/udf that executes if the context fails
	 */
	function when( required permissions, required success, fail ){
		arguments.permissions = arrayWrap( arguments.permissions );
		if ( has( arguments.permissions ) ) {
			arguments.success( getAuthService().getUser(), arguments.permissions );
		} else if ( !isNull( arguments.fail ) ) {
			arguments.fail( getAuthService().getUser(), arguments.permissions );
		}
		return this;
	}

	/**
	 * This method will verify that ALL permissions must exist in the currently logged in user.
	 *
	 * - If the result is true, then it will execute the success closure/lambda or udf.
	 * - If the restul is false, then it will execute the fail closure/lambda or udf
	 *
	 * The success or fail closures/lambdas/udfs must match the following signature
	 *
	 * <pre>
	 * function( user, permissions ){}
	 * ( user, permissions ) => {}
	 * </pre>
	 *
	 * They receive the currently logged in user and the permissions that where evaluated
	 *
	 * @permissions One, a list or an array of permissions
	 * @success     The closure/lambda/udf that executes if the context passes
	 * @fail        The closure/lambda/udf that executes if the context fails
	 */
	function whenAll( required permissions, required success, fail ){
		arguments.permissions = arrayWrap( arguments.permissions );
		if ( all( arguments.permissions ) ) {
			arguments.success( getAuthService().getUser(), arguments.permissions );
		} else if ( !isNull( arguments.fail ) ) {
			arguments.fail( getAuthService().getUser(), arguments.permissions );
		}
		return this;
	}

	/**
	 * This method will verify that NONE of the permissions must exist in the currently logged in user.
	 *
	 * - If the result is true, then it will execute the success closure/lambda or udf.
	 * - If the restul is false, then it will execute the fail closure/lambda or udf
	 *
	 * The success or fail closures/lambdas/udfs must match the following signature
	 *
	 * <pre>
	 * function( user, permissions ){}
	 * ( user, permissions ) => {}
	 * </pre>
	 *
	 * They receive the currently logged in user and the permissions that where evaluated
	 *
	 * @permissions One, a list or an array of permissions
	 * @success     The closure/lambda/udf that executes if the context passes
	 * @fail        The closure/lambda/udf that executes if the context fails
	 */
	function whenNone( required permissions, required success, fail ){
		arguments.permissions = arrayWrap( arguments.permissions );
		if ( none( arguments.permissions ) ) {
			arguments.success( getAuthService().getUser(), arguments.permissions );
		} else if ( !isNull( arguments.fail ) ) {
			arguments.fail( getAuthService().getUser(), arguments.permissions );
		}
		return this;
	}

	/**
	 * This is the method proxy injected into the request context that will act like the
	 * `secureView()` method velow
	 *
	 * @permissions One, a list or an array of permissions
	 * @successView The view to set in the request context if the permissions pass
	 * @failView    The view to set in the request context if the permissions fails, optional
	 */
	function secureViewProxy(
		required permissions,
		required successView,
		failView
	){
		arguments.event = this;
		controller
			.getWireBox()
			.getInstance( dsl = "@cbSecurity" )
			.secureView( argumentCollection = arguments );
		return this;
	}

	/**
	 * This method is injected into all request contex's in order to allow you to easily
	 * switch between views if the permissions are not found in the user.
	 *
	 * @event       The proxied request context
	 * @permissions One, a list or an array of permissions
	 * @successView The view to set in the request context if the permissions pass
	 * @failView    The view to set in the request context if the permissions fails, optional
	 */
	function secureView(
		required event,
		required permissions,
		required successView,
		failView
	){
		if ( has( arguments.permissions ) ) {
			arguments.event.setView( arguments.successView );
		} else if ( !isNull( arguments.failView ) ) {
			arguments.event.setView( arguments.failView );
		}
	}

	/**
	 * Get Real IP, by looking at clustered, proxy headers and locally.
	 *
	 * @trustUpstream If true, we check the forwarded headers first, else we don't
	 */
	string function getRealIP( boolean trustUpstream = true ){
		// When going through a proxy, the IP can be a delimtied list, thus we take the last one in the list
		if ( arguments.trustUpstream ) {
			var headers = getHTTPRequestData( false ).headers;
			if ( structKeyExists( headers, "x-cluster-client-ip" ) ) {
				return trim( listLast( headers[ "x-cluster-client-ip" ] ) );
			}
			if ( structKeyExists( headers, "X-Forwarded-For" ) ) {
				return trim( listFirst( headers[ "X-Forwarded-For" ] ) );
			}
		}

		return len( cgi.remote_addr ) ? trim( listFirst( cgi.remote_addr ) ) : "127.0.0.1";
	}

	/**
	 * Get the real host by looking at the upstreams if trusted or not
	 *
	 * @trustUpstream If true, we check the forwarded headers first, else we don't
	 */
	string function getRealHost( boolean trustUpstream = true ){
		var headers = getHTTPRequestData( false ).headers;
		// When going through a proxy, the IP can be a delimtied list, thus we take the last one in the list
		if ( arguments.trustUpstream ) {
			if ( structKeyExists( headers, "x-forwarded-host" ) ) {
				return trim( listFirst( headers[ "x-forwarded-host" ] ) );
			}
		}

		return headers.keyExists( "host" ) ? headers[ "host" ] : "none";
	}


	/**
	 * Generate a random, secure password using several options
	 *
	 * @length  The length of the password. Defaults to 32 characters
	 * @letters Use letters
	 * @numbers Use numbers
	 * @symbols Use symbols
	 *
	 * @return A secure random password
	 */
	function createPassword(
		numeric length  = 32,
		boolean letters = true,
		boolean numbers = true,
		boolean symbols = true
	){
		var characters = [];

		// cfformat-ignore-start
		_when( arguments.letters, () => characters.append( [
            'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k',
            'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v',
            'w', 'x', 'y', 'z', 'A', 'B', 'C', 'D', 'E', 'F', 'G',
            'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R',
            'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z'
        ], true ) )
		._when( arguments.numbers, () => characters.append( [
            '0', '1', '2', '3', '4', '5', '6', '7', '8', '9'
        ], true ) )
		._when( arguments.symbols, () => characters.append( [
            '~', '!', '##', '$', '%', '^', '&', '*', '(', ')', '-',
            '_', '.', ',', '<', '>', '?', '/', '\', '{', '}', '[',
            ']', '|', ':', ';'
        ], true ) );
		// cfformat-ignore-end

		return repeatString( "1", arguments.length )
			.listToArray( "" )
			.map( () => characters[ randRange( 1, characters.len() ) ] )
			.toList( "" );
	}


	/***************************************************************/
	/* Private Methods
	/***************************************************************/

	/**
	 * convert one or a list of permissions to an array, if it's an array we don't touch it
	 *
	 * @items One, a list or an array
	 */
	private function arrayWrap( required items ){
		return isArray( arguments.items ) ? items : listToArray( items );
	}

	/**
	 * TODO: Migrate from FlowHelpers once ColdBox 7 goes gold.
	 * This function evaluates the target boolean expression and if `true` it will execute the `success` closure
	 * else, if the `failure` closure is passed, it will execute it.
	 *
	 * @target  The boolean evaluator, this can be a boolean value
	 * @success The closure/lambda to execute if the boolean value is true
	 * @failure The closure/lambda to execute if the boolean value is false
	 *
	 * @return Returns itself
	 */
	private function _when(
		required boolean target,
		required success,
		failure
	){
		if ( arguments.target ) {
			arguments.success();
		} else if ( !isNull( arguments.failure ) ) {
			arguments.failure();
		}
		return variables;
	}

}
