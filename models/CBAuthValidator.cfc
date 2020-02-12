/**
 * Copyright since 2016 by Ortus Solutions, Corp
 * www.ortussolutions.com
 * ---
 * This is the core validator which leverages CF Security via cflogin and cfloginuser
 * https://helpx.adobe.com/coldfusion/developing-applications/developing-cfml-applications/securing-applications/using-coldfusion-security-tags-and-functions.html
 */
component singleton {

	// Injection
	property name="cbauth" inject="authenticationService@cbauth";

	/**
	 * This function is called once an incoming event matches a security rule.
	 * You will receive the security rule that matched and an instance of the
	 * ColdBox controller.
	 *
	 * You must return a struct with two keys:
	 * - allow:boolean True, user can continue access, false, invalid access actions will ensue
	 * - type:string(authentication|authorization) The type of block that ocurred.  Either an authentication or an authorization issue.
	 * - messages:string Info/debug messages
	 *
	 * @return { allow:boolean, type:authentication|authorization, messages:string }
	 */
	struct function ruleValidator( required rule, required controller ){
		return validateSecurity( arguments.rule.permissions );
	}

	/**
	 * This function is called once access to a handler/action is detected.
	 * You will receive the secured annotation value and an instance of the ColdBox Controller
	 *
	 * You must return a struct with two keys:
	 * - allow:boolean True, user can continue access, false, invalid access actions will ensue
	 * - type:string(authentication|authorization) The type of block that ocurred.  Either an authentication or an authorization issue.
	 * - messages:string Info/debug messages
	 *
	 * @return { allow:boolean, type:authentication|authorization, messages:string }
	 */
	struct function annotationValidator( required securedValue, required controller ){
		return validateSecurity( arguments.securedValue );
	}

	/**
	 * Validate Security via CBAuth
	 *
	 * @permissions
	 */
	private function validateSecurity( required permissions ){
		var results = {
			"allow"    : false,
			"type"     : "authentication",
			"messages" : ""
		};

		// Are we logged in?
		if ( variables.cbauth.isLoggedIn() ) {
			// Do we have any permissions?
			if ( listLen( arguments.permissions ) ) {
				results.allow = variables.cbauth.getUser().hasPermission( arguments.permissions );
				results.type  = "authorization";
			} else {
				// We are satisfied!
				results.allow = true;
			}
		}

		return results;
	}

}
