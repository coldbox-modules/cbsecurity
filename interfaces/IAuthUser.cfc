/**
 * Copyright since 2016 by Ortus Solutions, Corp
 * www.ortussolutions.com
 * ---
 * If you use a user with a user service or authentication service, it must implement this interface
 */
interface{

    /**
     * Return the unique identifier for the user
     */
    function getId();

    /**
     * Verify if the user has the permission passed in
     *
     * @permission A single permission to check for access
     *
     */
    boolean function hasPermission( required permission );

}