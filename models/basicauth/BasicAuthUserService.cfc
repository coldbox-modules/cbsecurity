/**
 * This is the basic auth user service that relies on the config's basicAuth.users configuration.
 */
component accessors="true" singleton {

	/*********************************************************************************************/
	/** DI **/
	/*********************************************************************************************/

	property name="settings"  inject="coldbox:moduleSettings:cbsecurity";
	property name="populator" inject="wirebox:populator";
	property name="wirebox"   inject="wirebox";

	variables.HASHING_ALGORITHM = "SHA-512";

	/**
	 * Constructor
	 */
	function init(){
		return this;
	}

	function onDIComplete(){
		// Normalize user storage
		param settings.basicAuth       = {};
		param settings.basicAuth.users = {};

		settings.basicAuth.users = settings.basicAuth.users.map( ( key, value ) => {
			var user      = getNewUserTemplate().append( arguments.value, true );
			user.username = key;
			user.password = hash( user.password, variables.HASHING_ALGORITHM );
			return user;
		} );
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
	BasicAuthUser function new() provider="BasicAuthUser@cbsecurity"{
	}

	/**
	 * Get a new user by id
	 *
	 * @id The id to get the user with
	 *
	 * @return The located user or a new un-loaded user object
	 */
	BasicAuthUser function retrieveUserById( required id ){
		var userRecord = variables.settings.basicAuth.users
			.filter( ( key, value ) => value.id == id )
			.reduce( ( results, key, value ) => value, {} );
		return populator.populateFromStruct( new (), userRecord );
	}

	BasicAuthUser function retrieveUserByUsername( required username ){
		return populator.populateFromStruct(
			new (),
			variables.settings.basicAuth.users.keyExists( arguments.username ) ? variables.settings.basicAuth.users[
				arguments.username
			] : {}
		);
	}

	boolean function isValidCredentials( username, password ){
		var oUser = retrieveUserByUsername( arguments.username );
		if ( !oUser.isLoaded() ) {
			return false;
		}

		return hash( arguments.password, variables.HASHING_ALGORITHM ) eq oUser.getPassword();
	}

}
