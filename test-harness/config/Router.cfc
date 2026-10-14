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

			// Non authenticating middleware
			route( "/mw/httpsNoRedirect" )
				.middleware( "EnsureHttps@cbsecurity" )
				.meta( { redirectToHttps : false } )
				.to( "mw.index" );
			route( "/mw/https" ).middleware( "EnsureHttps@cbsecurity" ).to( "mw.index" );

			route( "/mw/ip/allowed" )
				.middleware( "AllowedIPs@cbsecurity" )
				.meta( { allowedIps : "10.0.0.0/8,127.0.0.1,::1" } )
				.to( "mw.index" );
			route( "/mw/ip/notAllowed" )
				.middleware( "AllowedIPs@cbsecurity" )
				.meta( { allowedIps : "203.0.113.0/24" } )
				.to( "mw.index" );
			route( "/mw/ip/unconfigured" ).middleware( "AllowedIPs@cbsecurity" ).to( "mw.index" );
			route( "/mw/ip/denied" )
				.middleware( "DenyIPs@cbsecurity" )
				.meta( { denyIps : "127.0.0.1,::1" } )
				.to( "mw.index" );
			route( "/mw/ip/notDenied" )
				.middleware( "DenyIPs@cbsecurity" )
				.meta( { denyIps : "203.0.113.0/24" } )
				.to( "mw.index" );

			route( "/mw/apikey/custom" )
				.middleware( "ApiKey@cbsecurity" )
				.meta( { apiKeys : [ "key-one" ], apiKeyParam : "token", apiKeyHeader : "x-token" } )
				.to( "mw.index" );
			route( "/mw/apikey/unconfigured" ).middleware( "ApiKey@cbsecurity" ).to( "mw.index" );
			route( "/mw/apikey" )
				.middleware( "ApiKey@cbsecurity" )
				.meta( { apiKeys : "key-one,key-two" } )
				.to( "mw.index" );

			route( "/mw/honeypot/loud" )
				.middleware( "Honeypot@cbsecurity" )
				.meta( { honeypotSilent : false, honeypotField : "nickname" } )
				.to( "mw.index" );
			route( "/mw/honeypot" ).middleware( "Honeypot@cbsecurity" ).to( "mw.index" );

			route( "/mw/csrf" ).middleware( "VerifyCsrf@cbsecurity" ).to( "mw.index" );

			route( "/mw/throttle/named" )
				.middleware( "Throttle@cbsecurity" )
				.meta( { throttle : "strict" } )
				.to( "mw.index" );
			route( "/mw/throttle/inline" )
				.middleware( "Throttle@cbsecurity" )
				.meta( { throttle : { maxAttempts : 1, decaySeconds : 60 } } )
				.to( "mw.index" );
			route( "/mw/throttle/unknown" )
				.middleware( "Throttle@cbsecurity" )
				.meta( { throttle : "nope" } )
				.to( "mw.index" );
			route( "/mw/throttle/badCache" )
				.middleware( "Throttle@cbsecurity" )
				.meta( { throttle : { cacheProvider : "doesNotExist" } } )
				.to( "mw.index" );

			route( pattern = "/mw/signed/:id", name = "mw.signed" )
				.middleware( "Signed@cbsecurity" )
				.to( "mw.index" );
			route( "/mw/link" ).to( "mw.link" );
			route( "/mw/hasSignature" ).to( "mw.hasSignature" );

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
