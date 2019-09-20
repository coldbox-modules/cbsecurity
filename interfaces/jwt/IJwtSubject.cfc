/**
 * Copyright since 2016 by Ortus Solutions, Corp
 * www.ortussolutions.com
 * ---
 * If you use the jwt services, then your jwt subject user must implement this interface
 */
interface{

    /**
     * A struct of custom claims to add to the JWT token
     */
    struct function getJwtCustomClaims();

    /**
     * This function returns an array of all the scopes that should be attached to the JWT token that will be used for authorization.
     */
    array function getJwtScopes();

}