/**
 * Copyright since 2016 by Ortus Solutions, Corp
 * www.ortussolutions.com
 * ---
 * This user service is based off a basic auth configuration of users in the application's security configuration.
 * A single ColdBox application can have a main dictionary of users and modules can collaborate users as well.
 */
component accessors="true" singleton {

	/*********************************************************************************************/
	/** DI **/
	/*********************************************************************************************/

	property name="settings"  inject="coldbox:moduleSettings:cbsecurity";
	property name="populator" inject="wirebox:populator";
	property name="wirebox"   inject="wirebox";

	/*********************************************************************************************/
	/** Static Settings **/
	/*********************************************************************************************/

	variables.DEFAULT_SETTINGS = {
		// Hashing algorithm to use
		"hashAlgorithm"  : "SHA-512",
		// Iterates the number of times the hash is computed to create a more computationally intensive hash.
		"hashIterations" : 5,
		// User storage
		"users"          : {}
	};

	/**
	 * Constructor
	 */
	function init(){
		return this;
	}

	function onDIComplete(){
		// Normalize settings
		variables.settings.basicAuth = duplicate( variables.DEFAULT_SETTINGS ).append(
			variables.settings.basicAuth,
			true
		);
		// Normalize User Storage + password encryption
		settings.basicAuth.users = settings.basicAuth.users.map( ( key, value ) => {
			var user      = getNewUserTemplate().append( arguments.value, true );
			user.username = key;
			user.password = hashSecurely( user.password );
			return user;
		} );
	}

	/**
	 * Hash the incoming target according to our hashing algorithm and settings
	 *
	 * @target The string target to hash
	 */
	string function hashSecurely( required string target ){
		return hash(
			arguments.target,
			variables.settings.basicAuth.hashAlgorithm,
			"UTF-8",
			variables.settings.basicAuth.hashIterations
		);
	}

	/**
	 * Get an array of registered users with this service
	 */
	array function getUsers(){
		return variables.settings.basicAuth.users.reduce( ( results, username, record ) => {
			arguments.record.delete( "password" );
			return results.append( arguments.record );
		}, [] );
	}

	/**
	 * Create a new user template for basic auth
	 */
	private function getNewUserTemplate(){
		return {
			"id"          : createUUID(),
			"username"    : "",
			"password"    : generateSecretKey( "blowfish", "256" ),
			"roles"       : [],
			"permissions" : []
		};
	}

	/**
	 * New User dispenser
	 */
	User function new() provider="User@cbsecurity"{
	}

	/**
	 * Get a new user by id
	 *
	 * @id The id to get the user with
	 *
	 * @return The located user or a new un-loaded user object
	 */
	User function retrieveUserById( required id ){
		var userRecord = variables.settings.basicAuth.users
			.filter( ( key, value ) => value.id == id )
			.reduce( ( results, key, value ) => value, {} );
		return populator.populateFromStruct( new (), userRecord );
	}

	/**
	 * Get a user by username
	 *
	 * @username The username to get the user with
	 *
	 * @return The valid user object representing the username or an empty user object
	 */
	User function retrieveUserByUsername( required username ){
		return populator.populateFromStruct(
			new (),
			variables.settings.basicAuth.users.keyExists( arguments.username ) ? variables.settings.basicAuth.users[
				arguments.username
			] : {}
		);
	}

	/**
	 * Verify if the incoming username and password are valid credentials in this user storage
	 *
	 * @username The username to test
	 * @password The password to test
	 *
	 * @return true if valid, else false
	 */
	boolean function isValidCredentials( required username, required password ){
		var oUser = retrieveUserByUsername( arguments.username );
		if ( !oUser.isLoaded() ) {
			return false;
		}

		return hashSecurely( arguments.password ) eq oUser.getPassword();
	}

}
