component{

	function init(){
		return this;
	}

	function getSecurityRules(){

		var qRules = queryNew( "rule_id,securelist,whitelist,roles,permissions,redirect" );

		queryAddRow( qRules, 1 );
		querySetCell( qrules, "rule_id", createUUID() );
		querySetCell( qrules, "securelist", "^user\..*, ^admin" );
		querySetCell( qrules, "whitelist", "user.login,user.logout,^main.*" );
		querySetCell( qrules, "roles", "admin" );
		querySetCell( qrules, "permissions", "WRITE" );
		querySetCell( qrules, "redirect", "user.login" );

		return qRules;
	}

	/**
	 * This function is called once an incoming event matches a security rule.
	 * You will receive the security rule that matched and an instance of the
	 * ColdBox controller.
	 *
	 * @return True, user can continue access, false, relocation will occur.
	 */
	struct function ruleValidator( required rule, required controller ){
		return { "allow" : true, type : "authentication" };
	}

	/**
	 * This function is called once access to a handler/action is detected.
	 * You will receive the secured annotation value and an instance of the ColdBox Controller
	 *
	 * @return True, user can continue access, false, invalid access actions will ensue
	 */
	struct function annotationValidator( required securedValue, required controller ){
		return { "allow" : true, type : "authentication" };
	}

}