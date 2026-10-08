/**
 * Copyright since 2016 by Ortus Solutions, Corp
 * www.ortussolutions.com
 * ---
 * Route middleware: the request must carry a valid JWT, whatever validator the firewall uses.
 *
 * <pre>
 * route( "/api/orders" ).middleware( "JwtAuth@cbsecurity" ).to( "orders.index" )
 * </pre>
 */
component extends="cbsecurity.models.middleware.Guard" singleton {

	function init(){
		return super.init( validator = "jwt" );
	}

}
