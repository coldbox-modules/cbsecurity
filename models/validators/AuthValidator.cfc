/**
 * Copyright since 2016 by Ortus Solutions, Corp
 * www.ortussolutions.com
 * ---
 * This is the core validator which leverages any Authentication Service
 * that implements cbsecurity.models.interfaces.IAuthService and any User
 * that implements cbsecurity.models.interfaces.IAuthUser
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
		return validateSecurity( permissions: arguments.rule.permissions, roles: arguments.rule.roles );
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
		return validateSecurity( permissions = arguments.securedValue );
	}

	/**
	 * Validate Security on the user
	 *
	 * @permissions The secured value of the annotation or the rule permissions
	 * @roles       Rule roles
	 *
	 * @return Security Results Struct: { allow : boolean, type : (authentication|authorization), messages : "" }
	 */
	private function validateSecurity( string permissions = "", string roles = "" ){
		var results = {
			"allow"    : false,
			"type"     : "authentication",
			"messages" : ""
		};
		var authService = variables.cbSecurity.getAuthService();

		// Normalize roles + perms
		arguments.roles       = arguments.roles.listToArray();
		arguments.permissions = arguments.permissions.listToArray();

		if ( authService.isLoggedIn() ) {
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
			if ( arrayLen( arguments.roles ) && structKeyExists( oUser, "hasRole" ) ) {
				for ( var thisRole in arguments.roles ) {
					if ( oUser.hasRole( thisRole ) ) {
						results.allow = true;
						break;
					}
				}
			}

			// Check Perms
			if ( arrayLen( arguments.permissions ) ) {
				for ( var thisPermission in arguments.permissions ) {
					if ( oUser.hasPermission( thisPermission ) ) {
						results.allow = true;
						break;
					}
				}
			}
		}

		return results;
	}

}
