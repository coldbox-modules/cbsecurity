/**
 * Copyright since 2016 by Ortus Solutions, Corp
 * www.ortussolutions.com
 * ---
 * This delegate allows for objects to get JWT custom claims and Custom Scopes
 * This delegate expects the following functions to be exposed in the $parent
 * - getPermissions()
 * - getRoles()
 */
component {

	/**
	 * A struct of custom claims to add to the JWT token
	 * By default we add the $parent's roles
	 */
	struct function getJWTCustomClaims( required struct payload ){
		return { "role" : $parent.getRoles().toList() };
	}

	/**
	 * This function returns an array of all the scopes that should be attached to the JWT token that will be used for authorization.
	 * By default we add the $parent's permissions
	 */
	array function getJWTScopes(){
		return $parent.getPermissions();
	}

}
