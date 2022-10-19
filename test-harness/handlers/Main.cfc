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
		try {
			var oUser = cbsecure().authenticate( rc.username ?: "", rc.password ?: "" );
			return "You are logged in!";
		} catch ( "InvalidCredentials" e ) {
			flash.put( "message", "Invalid credentials, try again!" );
			relocate( "main/login" );
		}
	}

	/**
	 * doLogout
	 */
	function doLogout( event, rc, prc ){
		cbsecure().logout();
		flash.put( "message", "Bye bye!" );
		relocate( "main/login" );
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

	function rotateSession(){
		var oldSession  = duplicate( session );
		var httpRequest = getPageContext().getRequest();

		oldSession.delete( "sessionid" );
		oldSession.delete( "urltoken" );

		httpRequest.getSession().invalidate();
		var newSession = httpRequest.getSession( true );

		newSession.setAttribute( "startTime", now() );
		oldSession.each( ( k, v ) => newSession.setAttribute( k, v ) );

		return newSession.getId();
	}

}
