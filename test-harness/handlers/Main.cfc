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


	// Run on first init
	any function onAppInit( event, rc, prc ){
	}

}
