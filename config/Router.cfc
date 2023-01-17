component {

	/**
	 * Security Router
	 */
	function configure(){
		// refresh token endpoint
		post( "/refreshtoken" ).to( "Jwt.refreshToken" );
		// visualizer
		route( "/" ).to( "Visualizer.index" );
	}

}
