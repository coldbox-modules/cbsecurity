/**
 * Copyright since 2016 by Ortus Solutions, Corp
 * www.ortussolutions.com
 * ---
 * If you register an authentication service with cbsecurity it must adhere to this interface
 */
interface{

    /**
     * Get the authenticated user
     *
     * @return User that implements IAuthUser
     * @throws NoUserLoggedIn
     */
    any function getUser();

    /**
     * Verifies if a user is logged in
     */
    boolean function isLoggedIn();

    /**
     * Attemps to log in a user
     *
     * @username The username to log in with
     * @password The password to log in with
     *
     * @throws InvalidCredentials
     */
    boolean function authenticate( required username, required password );

    /**
     * Logs a user into the system
     *
     * @user The user object that implements IAuthUser
     */
    function login( required user );

    /**
     * Logs out the currently logged in user from the system
     */
    function logout();


}