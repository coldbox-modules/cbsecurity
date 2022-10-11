component {

	/**
	 * Security Router
	 */
	function configure(){
		post( "/refreshtoken" ).to( "Home.refreshToken" );
		route( "/" ).to( "Home.index" );
	}

}
