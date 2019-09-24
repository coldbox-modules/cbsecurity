/**
 * Visualize system security rules
 */
component {

	property name="cbSecurity" inject="coldbox:interceptor:cbsecurity@global";

	function index( event, rc, prc ){
		prc.properties = cbSecurity.getProperties();

		// If not enabled or in production, just 404 it
		if ( !prc.properties.enableSecurityVisualizer || getSetting( "environment" ) == "production" ) {
			event.setHTTPHeader( statusCode = 404, statusText = "page not found" );
			return "Page Not Found";
		}

		event.setView( "home/index" );
	}

}
