component {

	/**
	 * Security Router
	 */
	function configure(){
		// refresh token endpoint
		post( "/refreshtoken" ).to( "Home.refreshToken" );
		// visualizer
		route( "/" ).to( "Home.index" );
	}

}
