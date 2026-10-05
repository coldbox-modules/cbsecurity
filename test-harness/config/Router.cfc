component {

	function configure(){
		// Route middleware needs ColdBox 8.2+ (the router has middlewareGroup)
		if ( structKeyExists( this, "middlewareGroup" ) ) {
			route( "/mw/open" ).to( "mw.index" );
			route( "/mw/authenticated" ).middleware( "Authenticated@cbsecurity" ).to( "mw.index" );
			route( "/mw/jwt" ).middleware( "JwtAuth@cbsecurity" ).to( "mw.index" );

			// Authorized: permissions and roles come from the route meta
			route( "/mw/authorized" )
				.middleware( "Authorized@cbsecurity" )
				.meta( { permissions  : "read" } )
				.to( "mw.index" );
			route( "/mw/admin" )
				.middleware( "Authorized@cbsecurity" )
				.meta( { permissions  : "admin" } )
				.to( "mw.index" );
			route( "/mw/all" )
				.middleware( "Authorized@cbsecurity" )
				.meta( { permissions  : [ "read", "write" ], mode  : "all" } )
				.to( "mw.index" );
			route( "/mw/allMissing" )
				.middleware( "Authorized@cbsecurity" )
				.meta( { permissions  : "read,admin", mode  : "all" } )
				.to( "mw.index" );
			route( "/mw/none" )
				.middleware( "Authorized@cbsecurity" )
				.meta( { permissions  : "admin", mode  : "none" } )
				.to( "mw.index" );
			route( "/mw/role" )
				.middleware( "Authorized@cbsecurity" )
				.meta( { roles  : "editor" } )
				.to( "mw.index" );
			route( "/mw/roleMissing" )
				.middleware( "Authorized@cbsecurity" )
				.meta( { roles  : "admin" } )
				.to( "mw.index" );
			// Authenticated only checks the login, it ignores the meta
			route( "/mw/authenticatedIgnoresMeta" )
				.middleware( "Authenticated@cbsecurity" )
				.meta( { permissions  : "admin" } )
				.to( "mw.index" );

			// Group level meta needs ColdBox 8.3+ (the router tracks groupMetaStack)
			if ( variables.keyExists( "groupMetaStack" ) ) {
				group(
					{
						pattern    : "/mw/group",
						middleware : [ "Authorized@cbsecurity" ],
						meta       : { permissions  : "admin" }
					},
					function(){
						route( "/inside" ).to( "mw.index" );
					}
				);
			}
		}

		// Default convention routing
		route( "/:handler/:action?" ).end();
	}

}
