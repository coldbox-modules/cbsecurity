/**
 * Copyright since 2016 by Ortus Solutions, Corp
 * www.ortussolutions.com
 * ---
 * This is the core validator which leverages CF Security via cflogin and cfloginuser
 * https://helpx.adobe.com/coldfusion/developing-applications/developing-cfml-applications/securing-applications/using-coldfusion-security-tags-and-functions.html
 */
component singleton{

	/**
	 * This function is called once an incoming event matches a security rule.
	 * You will receive the security rule that matched and an instance of the
	 * ColdBox controller.
	 *
	 * @return True, user can continue access, false, relocation will occur.
	 */
	boolean function userValidator( required rule, required controller ){
		// Are we logged in?
		if( isUserLoggedIn() ){

			// Do we have any roles?
			if( listLen( arguments.rule.roles ) ){
				return 	isUserInAnyRole( arguments.rule.roles );
			}

			// We are satisfied!
			return true;
		}

		return false;
	}

}