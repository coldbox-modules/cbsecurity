/**
 * Copyright since 2016 by Ortus Solutions, Corp
 * www.ortussolutions.com
 * ---
 * This is a delegate only class to allow your application objects to deal with
 * authentication features via delegation.
 */
component singleton accessors="true" {

	// DI
	property name="cbSecurity" inject="cbSecurity@cbsecurity";
	property name="jwtService" inject="JwtService@cbSecurity";

	/**
	 * Retrieve the Jwt Auth Service
	 */
	function jwtAuth(){
		return variables.jwtService;
	}

	/**
	 * Retrieve the CBSecurity Service Object
	 */
	function cbSecure(){
		return variables.cbsecurity;
	}

	/**
	 * Retrieve the Authentication Service
	 */
	function auth(){
		return variables.cbsecurity.getAuthService();
	}

}
