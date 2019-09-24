component singleton {

	property name="bcrypt" inject="@BCrypt";
	// To populate objects from data
	property name="populator" inject="wirebox:populator";
	// To create new User instances
	property name="wirebox" inject="wirebox";

	// Function Aliases
	variables.get = this.get = variables.retrieveUserById;

	function init(){
		return this;
	}

	User function new() provider="User";

	User function retrieveUserById( required id ){
		return populator.populateFromQuery( new (), queryExecute( "SELECT * FROM `users` WHERE `id` = ?", [ id ] ) );
	}

	User function retrieveUserByUsername( required username ){
		return populator.populateFromQuery(
			new (),
			queryExecute( "SELECT * FROM `users` WHERE `username` = ?", [ username ] )
		);
	}

	boolean function isValidCredentials( username, password ){
		var oUser = retrieveUserByUsername( username );
		if ( !oUser.isLoaded() ) {
			return false;
		}

		return bcrypt.checkPassword( password, oUser.getPassword() );
	}

	/**
	 * create a user
	 */
	function create( required user ){
		queryExecute(
			"
				INSERT INTO `users` ( `name`, `email`, `username`, `password` )
				VALUES ( ?, ?, ?, ? )
			",
			[
				arguments.user.getName(),
				arguments.user.getEmail(),
				arguments.user.getUsername(),
				bcrypt.hashPassword( arguments.user.getPassword() )
			],
			{ result : "local.result" }
		);

		user.setId( result.generatedKey );
		return user;
	}

}
