/**
 * Copyright since 2016 by Ortus Solutions, Corp
 * www.ortussolutions.com
 * ---
 * This is the core validator which leverages CF Security via cflogin and cfloginuser
 * https://helpx.adobe.com/coldfusion/developing-applications/developing-cfml-applications/securing-applications/using-coldfusion-security-tags-and-functions.html
 */
component singleton threadsafe {

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
		return validateSecurity( arguments.rule.roles );
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
		return validateSecurity( arguments.securedValue );
	}

	/**
	 * Validate Security
	 *
	 * @roles
	 */
	private function validateSecurity( required roles ){
		var results = {
			"allow"    : false,
			"type"     : "authentication",
			"messages" : ""
		};

		// Are we logged in?
		if ( isUserLoggedIn() ) {
			// Do we have any roles?
			if ( listLen( arguments.roles ) ) {
				results.allow = isUserInAnyRole( arguments.roles );
				results.type  = "authorization";
			} else {
				// We are satisfied!
				results.allow = true;
			}
		}

		return results;
	}

}
