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
	 * @throws NoUserLoggedIn : If the user is not logged in
	 *
     * @return User that implements IAuthUser
     */
    any function getUser();

    /**
     * Verifies if a user is logged in
     */
    boolean function isLoggedIn();

    /**
     * Try to authenticate a user into the system. If the authentication fails an exception is thrown, else the logged in user object is returned
     *
     * @username The username to log in with
     * @password The password to log in with
     *
     * @throws InvalidCredentials
	 *
	 * @return User : The logged in user object
     */
    any function authenticate( required username, required password );

    /**
	 * Login a user into our persistent scopes
	 *
	 * @user The user object to log in
	 *
	 * @return The same user object so you can do functional goodness
	 */
    function login( required user );

    /**
     * Logs out the currently logged in user from the system
     */
    function logout();


}