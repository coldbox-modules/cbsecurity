/**
 * Copyright since 2016 by Ortus Solutions, Corp
 * www.ortussolutions.com
 * ---
 * Route middleware: the request must carry valid HTTP Basic credentials, whatever validator the firewall uses.
 *
 * <pre>
 * route( "/internal/stats" ).middleware( "BasicAuth@cbsecurity" ).to( "stats.index" )
 * </pre>
 */
component extends="cbsecurity.models.middleware.Guard" singleton {

	function init(){
		return super.init( validator = "basic" );
	}

}
