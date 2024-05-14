/**
 * I am a new handler
 */
component {

	/* 
		coldbox.cfc rules have been configured with the following ips 
		127.0.0.1, 
		172.17.1.140, 
		172.17.2.0/24" 
	*/

	function index( event, rc, prc ){
		event.setView( "IPTester/index" );
	}



	function fail( event, rc, prc ){
		event.setView( "IPTester/fail" );
	}


}
