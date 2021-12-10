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

	property name="settings" inject="coldbox:moduleSettings:cbsecurity";
	property name="log" inject="logbox:logger:{this}";
	property name="wirebox" inject="wirebox";


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

	/**
	 * Constructor
	 */
	function init(){
		return this;
	}

	/**
	 * Get the user service object defined accordingly in the settings
	 *
	 * @throws IncompleteConfiguration
	 *
	 * @return cbsecurity.interfaces.IUserService
	 */
	any function getUserService(){
		// If loaded, use it!
		if ( !isNull( variables.userService ) ) {
			return variables.userService;
		}

		// Check and Load Baby!
		if ( !len( variables.settings.userService ) ) {
			throw(
				message = "No [userService] provided in the settings.  Please set it in the `config/ColdBox.cfc` under `moduleSettings.cbsecurity.userService`.",
				type    = "IncompleteConfiguration"
			);
		}

		variables.userService = variables.wirebox.getInstance( variables.settings.userService );

		return variables.userService;
	}

	/**
	 * Get the authentication service defined accordingly in the settings
	 *
	 * @throws IncompleteConfiguration
	 *
	 * @return cbsecurity.interfaces.IAuthService
	 */
	any function getAuthService(){
		// If loaded, use it!
		if ( !isNull( variables.authService ) ) {
			return variables.authService;
		}

		// Check and Load Baby!
		if ( !len( variables.settings.authenticationService ) ) {
			throw(
				message = "No [authService] provided in the settings.  Please set in `config/ColdBox.cfc` under `moduleSettings.cbsecurity.authenticationService`.",
				type    = "IncompleteConfiguration"
			);
		}

		variables.authService = variables.wirebox.getInstance(
			variables.settings.authenticationService
		);

		return variables.authService;
	}

	/***************************************************************/
	/* Verification Methods
	/***************************************************************/

	/**
	 * Verify if the incoming permissions exist in the currently authenticated user.
	 * All permissions are Or'ed together
	 *
	 * @throws NoUserLoggedIn
	 *
	 * @permissions One, a list or an array of permissions
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
	 * @throws NoUserLoggedIn
	 *
	 * @permissions One, a list or an array of permissions
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
	 * @throws NoUserLoggedIn
	 *
	 * @permissions One, a list or an array of permissions
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
	 * @throws NoUserLoggedIn
	 *
	 * @user The user to test for equality
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
	 * @throws NotAuthorized
	 *
	 * @permissions One, a list or an array of permissions
	 * @message The error message to throw in the exception
	 *
	 * @returns CBSecurity
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
	 * @throws NotAuthorized
	 *
	 * @permissions One, a list or an array of permissions
	 * @message The error message to throw in the exception
	 *
	 * @returns CBSecurity
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
	 * @throws NotAuthorized
	 *
	 * @permissions One, a list or an array of permissions
	 * @message The error message to throw in the exception
	 *
	 * @returns CBSecurity
	 */
	CBSecurity function secureNone(
		required permissions,
		message = variables.DEFAULT_ERROR_MESSAGE
	){
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
	 * @throws NotAuthorized
	 *
	 * @context A closure/lambda/udf that returns boolean, or a boolean expression
	 * @message The error message to throw in the exception
	 *
	 * @returns CBSecurity
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
	 * @throws NoUserLoggedIn
	 * @throws NotAuthorized
	 *
	 * @user The user to test for equality
	 * @message The error message to throw in the exception
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
	 * @permissions One, a list or an array of permissions
	 * @success The closure/lambda/udf that executes if the context passes
	 * @fail The closure/lambda/udf that executes if the context fails
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
	 * @success The closure/lambda/udf that executes if the context passes
	 * @fail The closure/lambda/udf that executes if the context fails
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
	 * @success The closure/lambda/udf that executes if the context passes
	 * @fail The closure/lambda/udf that executes if the context fails
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
	 * @failView The view to set in the request context if the permissions fails, optional
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
	 * @event The proxied request context
	 * @permissions One, a list or an array of permissions
	 * @successView The view to set in the request context if the permissions pass
	 * @failView The view to set in the request context if the permissions fails, optional
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
	 */
	string function getRealIP(){
		var headers = getHTTPRequestData( false ).headers;

		// When going through a proxy, the IP can be a delimtied list, thus we take the last one in the list

		if ( structKeyExists( headers, "x-cluster-client-ip" ) ) {
			return trim( listLast( headers[ "x-cluster-client-ip" ] ) );
		}
		if ( structKeyExists( headers, "X-Forwarded-For" ) ) {
			return trim( listFirst( headers[ "X-Forwarded-For" ] ) );
		}

		return len( cgi.remote_addr ) ? trim( listFirst( cgi.remote_addr ) ) : "127.0.0.1";
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

}
