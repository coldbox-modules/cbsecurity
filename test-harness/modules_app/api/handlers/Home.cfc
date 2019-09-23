/**
 * A ColdBox Event Handler
 */
component{

	property name="jwtSerivce" 		inject="jwtService@cbsecurity";
	property name="userService" 	inject="userService";

	/**
	 * Home page
	 */
	function index( event, rc, prc ){
		return {
			"error" 	: false,
			"data" 		: "",
			"message" 	: "Welcome to the cbsecurity services"
		};
	}


	/**
	* onInvalidAuth
	*/
	function onInvalidAuth( event, rc, prc ){
		event.setHTTPHeader( statusCode=401, statusText="Not Authenticated" );
		return {
			"error" 	: true,
			"data" 		: "",
			"message" 	: "You need to be authenticated"
		};
	}

	/**
	* onInvalidAuth
	*/
	function onInvalidAuthorization( event, rc, prc ){
		event.setHTTPHeader( statusCode=403, statusText="Not Authorized" );
		return {
			"error" 	: true,
			"data" 		: "",
			"message" 	: "You need to be authorized"
		};
	}


	/**
	* login
	*/
	function login( event, rc, prc ){
		param rc.username = "";
		param rc.password = "";

		try{
			var token = variables.jwtService.attempt( rc.username, rc.password );
			return {
				"error" 	: true,
				"data" 		: token,
				"message" 	: "Bearer token created."
			};
		} catch ( any "InvalidCredentials" ) {
			return onInvalidAuth( argumentCollection=arguments );
		}

	}

	/**
	* register
	*/
	function register( event, rc, prc ){
		param rc.firstName = "";
		param rc.lastName  = "";
		param rc.username  = "";
		param rc.password  = "";

		prc.oUser = populateModel( "User" );
		userService.create( prc.oUser );

		var token = jwtService.fromuser( prc.oUser );
		return {
			"error" 	: true,
			"data" 		: token,
			"message" 	: "User registered correctly and Bearer token created."
		};
	}

	/**
	* logout
	*/
	function logout( event, rc, prc ){
		auth().logout();
		return {
			"error" 	: false,
			"data" 		: "",
			"message" 	: "Successfully logged out"
		};
	}

}
