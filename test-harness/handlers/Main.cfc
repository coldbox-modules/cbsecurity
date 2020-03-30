/**
 * My Event Handler Hint
 */
component {

	// Index
	any function index( event, rc, prc ){
		event.setView( "main/index" );
	}

	// Index
	any function auth( event, rc, prc ){
		return "authorization";
	}

	/**
	 * login
	 */
	function login( event, rc, prc ){
		event.setView( "main/login" );
	}

	/**
	 * doLogin
	 */
	function doLogin( event, rc, prc ){
		return "login";
	}


	/**
	* cbSecureMixin
	*/
	function cbSecureMixin( event, rc, prc ){
		cbsecure().getAuthService();
		cbSecure().getUserService();
		return cbsecure().getSettings();
	}

	function secureView( event, rc, prc ){
		event.secureView( "test", "main/index" );
	}

}