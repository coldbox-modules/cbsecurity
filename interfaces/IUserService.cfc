/**
 * Copyright since 2016 by Ortus Solutions, Corp
 * www.ortussolutions.com
 * ---
 * If you use our jwt services, then your user service must implement this interface
 */
interface{

	/**
	 * Verify if the incoming username/password are valid credentials.
	 *
	 * @username The username
	 * @password The password
	 */
	boolean function isValidCredentials( required username, required password );

	/**
	 * Retrieve a user by username
	 *
	 * @return User that implements JWTSubject and/or IAuthUser
	 */
	function retrieveUserByUsername( required username );

	/**
	 * Retrieve a user by unique identifier
	 *
	 * @id The unique identifier
	 *
	 * @return User that implements JWTSubject and/or IAuthUser
	 */
	function retrieveUserById( required id );
}