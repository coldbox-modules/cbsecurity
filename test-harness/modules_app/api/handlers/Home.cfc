/**
 * A ColdBox Event Handler
 */
component {

	property name="userService" inject="userService";

	/**
	 * Home page
	 */
	function index( event, rc, prc ){
		return { "error" : false, "data" : "", "message" : "Welcome to the cbsecurity services" };
	}


	/**
	 * onInvalidAuth
	 */
	function onInvalidAuth( event, rc, prc ){
		event.setHTTPHeader( statusCode = 401, statusText = "Not Authenticated" );
		return { "error" : true, "data" : "", "message" : "You need to be authenticated" };
	}

	/**
	 * onInvalidAuth
	 */
	function onInvalidAuthorization( event, rc, prc ){
		event.setHTTPHeader( statusCode = 403, statusText = "Not Authorized" );
		return { "error" : true, "data" : "", "message" : "You need to be authorized" };
	}

	/**
	 * login
	 */
	function login( event, rc, prc ){
		param rc.username = "";
		param rc.password = "";

		try {
			var token = jwtAuth().attempt( rc.username, rc.password );
			return {
				"error"   : true,
				"data"    : token,
				"message" : "Bearer token created and it expires in #jwtAuth().getSettings().jwt.expiration# minutes"
			};
		} catch ( "InvalidCredentials" e ) {
			event.setHTTPHeader( statusCode = 401, statusText = "Not Authorized" );
			return { "error" : true, "data" : "", "message" : "Invalid Credentials" };
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

		var token = jwtAuth().fromuser( prc.oUser );
		return {
			"error"   : true,
			"data"    : token,
			"message" : "User registered correctly and Bearer token created and it expires in #jwtAuth().getSettings().jwt.expiration# minutes"
		};
	}

	/**
	 * logout
	 */
	function logout( event, rc, prc ){
		jwtAuth().logout();
		return { "error" : false, "data" : "", "message" : "Successfully logged out" };
	}

	/**
	 * gen
	 */
	function gen( event, rc, prc ){
		var timestamp = now();
		var userId    = 123;
		return jwtAuth().encode( {
			// Issuing authority
			"iss"    : event.getHTMLBaseURL(),
			// Token creation
			"iat"    : jwtAuth().toEpoch( timestamp ),
			// The subject identifier
			"sub"    : 123,
			// The token expiration
			"exp"    : jwtAuth().toEpoch( dateAdd( "s", 1, timestamp ) ),
			// The unique identifier of the token
			"jti"    : hash( timestamp & userId ),
			// Get the user scopes for the JWT token
			"scopes" : [],
			"role"   : "admin"
		} );
	}


	/**
	 * dec
	 */
	function dec( event, rc, prc ){
		var token = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzUxMiJ9.eyJpYXQiOjE1NjkyNzI0NjQsInJvbGUiOiJhZG1pbiIsInNjb3BlcyI6W10sImlzcyI6Imh0dHA6Ly8xMjcuMC4wLjE6NTY1OTYvIiwic3ViIjoxMjMsImV4cCI6MTU2OTI3MjQ2NSwianRpIjoiRTRDNEM3MDdFNjA1MzQwRDkxRDNCMDBCMkI4NTdFNDMifQ.N2rT_b_Xp8e9Hw0O7yVork6Fg8aC7RKf0Fv-Bmu7Iv5CVvFrmk1gkF_oKeXmcl22MiwhB2oQJhMNZiFa5OfSKw";
		return jwtAuth().decode( token );
	}

}
