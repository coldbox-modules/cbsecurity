/**
 * Copyright since 2016 by Ortus Solutions, Corp
 * www.ortussolutions.com
 * ---
 * This is the basic auth validator.  It will talk to the configured authentication service for maintaining the valid users logged in and providing a logout mechanism.
 * cbAuth leverages the `cbAuthUserService` when using this type of validator by default.
 */
component singleton threadsafe {

	// DI
	property name="cbSecurity" inject="CBSecurity@cbSecurity";
	property name="log"        inject="logbox:logger:{this}";

	/**
	 * This function is called once an incoming event matches a security rule.
	 * You will receive the security rule that matched and an instance of the
	 * ColdBox controller.
	 *
	 * You must return a struct with three keys:
	 * - allow:boolean True, user can continue access, false, invalid access actions will ensue
	 * - type:string(authentication|authorization) The type of block that ocurred.  Either an authentication or an authorization issue.
	 * - messages:string Info/debug messages
	 *
	 * @return { allow:boolean, type:string(authentication|authorization), messages:string }
	 */
	struct function ruleValidator( required rule, required controller ){
		return validateSecurity(
			arguments.rule.roles,
			arguments.rule.permissions,
			arguments.controller
		);
	}

	/**
	 * This function is called once access to a handler/action is detected.
	 * You will receive the secured annotation value and an instance of the ColdBox Controller
	 *
	 * You must return a struct with three keys:
	 * - allow:boolean True, user can continue access, false, invalid access actions will ensue
	 * - type:string(authentication|authorization) The type of block that ocurred.  Either an authentication or an authorization issue.
	 * - messages:string Info/debug messages
	 *
	 * @return { allow:boolean, type:string(authentication|authorization), messages:string }
	 */
	struct function annotationValidator( required securedValue, required controller ){
		return validateSecurity( permissions: arguments.securedValue, controller: arguments.controller );
	}

	/**
	 * Validate Security via CBAuth
	 *
	 * @roles       The roles you need to access
	 * @permissions The permissions you need to access
	 * @controller  The ColdBox controller
	 */
	private function validateSecurity(
		roles       = "",
		permissions = "",
		required controller
	){
		var event   = arguments.controller.getRequestService().getContext();
		var results = {
			"allow"          : false,
			"type"           : "authentication",
			"messages"       : "",
			"processActions" : true
		};
		var authService = variables.cbSecurity.getAuthService();

		// Normalize roles + perms
		arguments.roles       = arguments.roles.listToArray();
		arguments.permissions = arguments.permissions.listToArray();

		// Verify Incoming Headers to see if we are authorizing already or we are already Authorized
		if ( !authService.isLoggedIn() OR len( event.getHTTPHeader( "Authorization", "" ) ) ) {
			// Verify incoming authorization
			var credentials = event.getHTTPBasicCredentials();
			try {
				authService.authenticate( credentials.username, credentials.password );
				results.allow = true;
			} catch ( "InvalidCredentials" e ) {
				// Not secure! Basic Auth Prompt
				event
					.setHTTPHeader(
						name  = "WWW-Authenticate",
						value = "basic realm='Please enter your credentials'"
					)
					.setHTTPHeader( name = "Cache-Control", value = "no-cache, must-revalidate, max-age=0" );
				results.processactions = false;
				return results;
			}
		}

		// If we are here, we are logged in, verify authorizations
		var oUser     = authService.getUser();
		// Authentication passed, we are on to authorization now
		results.type  = "authorization";
		// Default to block, unless we validate either roles or permissions
		results.allow = arrayLen( arguments.roles ) || arrayLen( arguments.permissions ) ? false : true;

		// Validate new interface if not, just warn
		// TODO: Change to just use the hasRole() by vNext : Compat for now.
		if ( !structKeyExists( oUser, "hasRole" ) ) {
			variables.log.warn(
				"CBSecurity User object does not implement the `hasRole()` method. Please add it."
			);
		}

		// Check roles
		if ( arrayLen( arguments.roles ) && structKeyExists( user, "hasRole" ) ) {
			if ( oUser.hasRole( arguments.roles ) ) {
				results.allow = true;
			}
		}

		// Check perms
		if ( arrayLen( arguments.permissions ) ) {
			if ( oUser.hasPermission( arguments.permissions ) ) {
				results.allow = true;
			}
		}

		return results;
	}

}
