/**
 * Copyright since 2016 by Ortus Solutions, Corp
 * www.ortussolutions.com
 * ---
 * If you use the jwt services, then your jwt subject user must implement this interface
 */
interface{

    /**
     * A struct of custom claims to add to the JWT token when creating it
	 *
	 * @payload The actual payload structure that was used in the request
	 *
	 * @return A structure of custom claims
     */
    struct function getJwtCustomClaims( required struct payload );

    /**
     * This function returns an array of all the scopes that should be attached to the JWT token that will be used for authorization.
     */
    array function getJwtScopes();

}
