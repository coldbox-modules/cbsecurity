/**
 * Copyright since 2016 by Ortus Solutions, Corp
 * www.ortussolutions.com
 * ---
 * Route middleware: the user must be logged in using the firewall's validator. Route metadata is ignored,
 * use `Authorized@cbsecurity` to also verify permissions or roles.
 *
 * <pre>
 * route( "/account" ).middleware( "Authenticated@cbsecurity" ).to( "account.index" )
 * </pre>
 */
component extends="cbsecurity.models.middleware.Guard" singleton {

	function init(){
		return super.init( useMeta = false );
	}

}
