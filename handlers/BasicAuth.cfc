/**
 * Basic Auth Handler
 */
component extends="coldbox.system.EventHandler" {

	/**
	 * Logout via basic auth
	 */
	function logout( event, rc, prc ){
		cbsecure().getAuthService().logout();
		event
			.setHTTPHeader( name = "WWW-Authenticate", value = "basic realm='Please enter your credentials'" )
			.setHTTPHeader( name = "Cache-Control", value = "no-cache, must-revalidate, max-age=0" )
			.renderData( data = "<h1>Logout Successful!</h1>", statusCode = 401 );
	}

}
