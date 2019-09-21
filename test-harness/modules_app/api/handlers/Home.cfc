/**
 * A ColdBox Event Handler
 */
component{

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


}
