/**
 * Route middleware specs. These use stub users so no database is required.
 */
component extends="coldbox.system.testing.BaseTestCase" appMapping="/root" {

	this.unloadColdbox = false;

	function beforeAll(){
		super.beforeAll();
	}

	function afterAll(){
		super.afterAll();
	}

	function run(){
		// Route specs need ColdBox 8.3+: execute() runs route middleware and groups can carry meta
		var skipRouteSpecs = function(){
			return !routeMiddlewareTestable();
		};

		describe( "Route Middleware", function(){
			beforeEach( function( currentSpec ){
				setup();
				cbauth   = getInstance( "authenticationService@cbauth" );
				firewall = getWireBox().getInstance( "interceptor-cbsecurity@global" );
				cbauth.logout();
			} );

			afterEach( function( currentSpec ){
				cbauth.logout();
			} );

			describe(
				title = "Authenticated@cbsecurity",
				skip  = skipRouteSpecs,
				body  = function(){
					it( "does not interfere with routes that do not use it", function(){
						var event = execute( route = "/mw/open", renderResults = true );
						expect( event.getRenderedContent() ).toBe( "mw ok" );
					} );

					it( "denies guests with the firewall's invalid authentication action", function(){
						var event = execute( route = "/mw/authenticated", renderResults = true );
						expect( event.getValue( "relocate_event" ) ).toBe( "main.index" );
						expect( event.getRenderedContent() ).notToBe( "mw ok" );
						expect( event.getPrivateValue( "cbSecurity_validatorResults" ).type ).toBe(
							"authentication"
						);
					} );

					it( "allows logged in users and stores them in the prc", function(){
						cbauth.login( buildUser() );
						var event = execute( route = "/mw/authenticated", renderResults = true );
						expect( event.getRenderedContent() ).toBe( "mw ok" );
						expect( event.valueExists( "relocate_event" ) ).toBeFalse();
						expect( event.getPrivateValue( "oCurrentUser" ).getId() ).toBe( 1 );
					} );

					it( "honors a block action", function(){
						var original = firewall.getProperty( "firewall" ).defaultAuthenticationAction;
						try {
							firewall.getProperty( "firewall" ).defaultAuthenticationAction = "block";
							var event      = execute( route = "/mw/authenticated", renderResults = true );
							var renderData = event.getRenderData();
							expect( renderData.statusCode ).toBe( 401 );
							expect( renderData.data ).toInclude( "Unauthorized" );
						} finally {
							firewall.getProperty( "firewall" ).defaultAuthenticationAction = original;
						}
					} );

					it( "honors an override action", function(){
						var original = firewall.getProperty( "firewall" ).defaultAuthenticationAction;
						try {
							firewall.getProperty( "firewall" ).defaultAuthenticationAction = "override";
							var event = execute( route = "/mw/authenticated", renderResults = true );
							expect( event.getCurrentEvent() ).toBe( "main.index" );
							expect( event.valueExists( "relocate_event" ) ).toBeFalse();
						} finally {
							firewall.getProperty( "firewall" ).defaultAuthenticationAction = original;
						}
					} );

					it( "announces the invalid authentication interception point", function(){
						structDelete( request, "mwSpy" );
						getController()
							.getInterceptorService()
							.registerInterceptor(
								interceptorClass = "tests.resources.MiddlewareSpyInterceptor",
								interceptorName  = "mwSpyInterceptor"
							);
						try {
							execute( route = "/mw/authenticated", renderResults = true );
						} finally {
							getController().getInterceptorService().unregister( "mwSpyInterceptor" );
						}
						expect( request ).toHaveKey( "mwSpy" );
						expect( request.mwSpy.source ).toBe( "middleware" );
						expect( request.mwSpy.type ).toBe( "authentication" );
					} );
				}
			);

			describe(
				title = "Authorized@cbsecurity",
				skip  = skipRouteSpecs,
				body  = function(){
					it( "denies guests as an authentication failure", function(){
						var event = execute( route = "/mw/authorized", renderResults = true );
						expect( event.getValue( "relocate_event" ) ).toBe( "main.index" );
						expect( event.getPrivateValue( "cbSecurity_validatorResults" ).type ).toBe(
							"authentication"
						);
					} );

					it( "allows a user with one of the route permissions", function(){
						cbauth.login( buildUser() );
						var event = execute( route = "/mw/authorized", renderResults = true );
						expect( event.getRenderedContent() ).toBe( "mw ok" );
					} );

					it( "denies a user without the route permissions as an authorization failure", function(){
						cbauth.login( buildUser() );
						var event = execute( route = "/mw/admin", renderResults = true );
						expect( event.getValue( "relocate_event" ) ).toBe( "main.index" );
						expect( event.getPrivateValue( "cbSecurity_validatorResults" ).type ).toBe(
							"authorization"
						);
						expect( event.getRenderedContent() ).notToBe( "mw ok" );
					} );

					it( "supports the all mode with an array of permissions", function(){
						cbauth.login( buildUser() );
						expect( execute( route = "/mw/all", renderResults = true ).getRenderedContent() ).toBe(
							"mw ok"
						);
						expect(
							execute( route = "/mw/allMissing", renderResults = true ).getValue( "relocate_event" )
						).toBe( "main.index" );
					} );

					it( "supports the none mode", function(){
						cbauth.login( buildUser() );
						expect( execute( route = "/mw/none", renderResults = true ).getRenderedContent() ).toBe(
							"mw ok"
						);
					} );

					it( "supports roles", function(){
						cbauth.login( buildUser() );
						expect( execute( route = "/mw/role", renderResults = true ).getRenderedContent() ).toBe(
							"mw ok"
						);
						expect(
							execute( route = "/mw/roleMissing", renderResults = true ).getValue( "relocate_event" )
						).toBe( "main.index" );
					} );

					it( "is applied with its meta to every route of a group", function(){
						cbauth.login( buildUser() );
						var event = execute( route = "/mw/group/inside", renderResults = true );
						expect( event.getValue( "relocate_event" ) ).toBe( "main.index" );
						expect( event.getRenderedContent() ).notToBe( "mw ok" );
					} );
				}
			);

			describe(
				title = "Authenticated@cbsecurity route meta",
				skip  = skipRouteSpecs,
				body  = function(){
					it( "ignores the route meta and only verifies the login", function(){
						cbauth.login( buildUser() );
						var event = execute( route = "/mw/authenticatedIgnoresMeta", renderResults = true );
						expect( event.getRenderedContent() ).toBe( "mw ok" );
					} );
				}
			);

			describe(
				title = "JwtAuth@cbsecurity",
				skip  = skipRouteSpecs,
				body  = function(){
					it( "denies requests without a token", function(){
						var event = execute( route = "/mw/jwt", renderResults = true );
						expect( event.getValue( "relocate_event" ) ).toBe( "main.index" );
						expect( event.getRenderedContent() ).notToBe( "mw ok" );
					} );
				}
			);

			describe( "Guard@cbsecurity", function(){
				// Use the block action so direct calls do not relocate
				beforeEach( function( currentSpec ){
					var settings = firewall.getProperty( "firewall" );
					originals    = {
						"authn" : settings.defaultAuthenticationAction,
						"authz" : settings.defaultAuthorizationAction
					};
					settings.defaultAuthenticationAction = "block";
					settings.defaultAuthorizationAction  = "block";
				} );

				afterEach( function( currentSpec ){
					var settings                         = firewall.getProperty( "firewall" );
					settings.defaultAuthenticationAction = originals.authn;
					settings.defaultAuthorizationAction  = originals.authz;
				} );

				function newGuard(){
					return getWireBox().getInstance( name = "Guard@cbsecurity", initArguments = arguments );
				}

				function runGuard( required guard ){
					var event = getRequestContext();
					return arguments.guard.preProcess(
						event,
						event.getCollection(),
						event.getPrivateCollection()
					);
				}

				it( "resolves the ready made middleware with the right validators", function(){
					expect( prepareMock( getInstance( "BasicAuth@cbsecurity" ) ).$getProperty( "validator" ) ).toBe(
						"BasicAuthValidator@cbsecurity"
					);
					expect( prepareMock( getInstance( "JwtAuth@cbsecurity" ) ).$getProperty( "validator" ) ).toBe(
						"JwtAuthValidator@cbsecurity"
					);
				} );

				it( "rejects an invalid mode", function(){
					// WireBox wraps constructor exceptions, so assert on the message
					expect( function(){
						newGuard( mode = "bogus" );
					} ).toThrow( regex = "mode \[bogus\] is invalid" );
				} );

				describe( "custom middleware extending Guard", function(){
					it( "uses its constructor permissions and ignores the route meta", function(){
						cbauth.login( buildUser() );
						var event = getRequestContext();
						// The route meta asks for a permission the user does not have
						event.setPrivateValue( "currentRouteMeta", { "permissions" : "admin" } );
						var custom = getWireBox().getInstance( "tests.resources.ReadOnlyMiddleware" );
						expect( runGuard( custom ) ).toBeFalse();
					} );

					it( "denies users without its constructor permissions", function(){
						cbauth.login(
							createStub()
								.$( "getId", 2 )
								.$( "hasPermission", false )
								.$( "hasRole", false )
						);
						var custom = getWireBox().getInstance( "tests.resources.ReadOnlyMiddleware" );
						expect( runGuard( custom ) ).toBeTrue();
					} );
				} );

				it( "reads the permissions from the current route meta", function(){
					cbauth.login( buildUser() );
					var event = getRequestContext();
					event.setPrivateValue( "currentRouteMeta", { "permissions" : "admin" } );
					expect( runGuard( newGuard() ) ).toBeTrue();
					event.setPrivateValue( "currentRouteMeta", { "permissions" : "read" } );
					expect( runGuard( newGuard() ) ).toBeFalse();
				} );

				describe( "mode any", function(){
					it( "allows when the user has one of the permissions", function(){
						cbauth.login( buildUser() );
						expect( runGuard( newGuard( permissions = "admin,read" ) ) ).toBeFalse();
					} );

					it( "accepts permissions as an array", function(){
						cbauth.login( buildUser() );
						expect( runGuard( newGuard( permissions = [ "admin", "write" ] ) ) ).toBeFalse();
					} );

					it( "denies as an authorization failure when no permission matches", function(){
						cbauth.login( buildUser() );
						expect( runGuard( newGuard( permissions = "admin" ) ) ).toBeTrue();
						expect( getRequestContext().getPrivateValue( "cbSecurity_validatorResults" ).type ).toBe(
							"authorization"
						);
					} );

					it( "denies guests as an authentication failure", function(){
						expect( runGuard( newGuard( permissions = "read" ) ) ).toBeTrue();
						expect( getRequestContext().getPrivateValue( "cbSecurity_validatorResults" ).type ).toBe(
							"authentication"
						);
					} );
				} );

				describe( "mode all", function(){
					it( "allows when the user has every permission", function(){
						cbauth.login( buildUser() );
						expect( runGuard( newGuard( permissions = "read,write", mode = "all" ) ) ).toBeFalse();
					} );

					it( "denies when one permission is missing", function(){
						cbauth.login( buildUser() );
						expect( runGuard( newGuard( permissions = "read,admin", mode = "all" ) ) ).toBeTrue();
						expect( getRequestContext().getPrivateValue( "cbSecurity_validatorResults" ).type ).toBe(
							"authorization"
						);
					} );

					it( "denies guests as an authentication failure", function(){
						expect( runGuard( newGuard( permissions = "read", mode = "all" ) ) ).toBeTrue();
						expect( getRequestContext().getPrivateValue( "cbSecurity_validatorResults" ).type ).toBe(
							"authentication"
						);
					} );
				} );

				describe( "mode none", function(){
					it( "allows when the user has none of the permissions", function(){
						cbauth.login( buildUser() );
						expect( runGuard( newGuard( permissions = "admin,delete", mode = "none" ) ) ).toBeFalse();
					} );

					it( "denies when the user has any of the permissions", function(){
						cbauth.login( buildUser() );
						expect( runGuard( newGuard( permissions = "admin,read", mode = "none" ) ) ).toBeTrue();
					} );
				} );

				describe( "roles", function(){
					it( "allows when the user has one of the roles", function(){
						cbauth.login( buildUser() );
						expect( runGuard( newGuard( roles = "admin,editor" ) ) ).toBeFalse();
					} );

					it( "denies when the user has none of the roles", function(){
						cbauth.login( buildUser() );
						expect( runGuard( newGuard( roles = "admin" ) ) ).toBeTrue();
					} );
				} );
			} );
		} );
	}

	/**
	 * Detects if the installed ColdBox can test route middleware: groups carry meta and execute() runs route middleware.
	 * Both shipped in ColdBox 8.3.0. We detect the features instead of the version so snapshots and BE builds work.
	 */
	private boolean function routeMiddlewareTestable(){
		return (
			fileRead( expandPath( "/coldbox/system/web/routing/Router.cfc" ) ).findNoCase( "groupMetaStack" ) > 0
			&&
			fileRead( expandPath( "/coldbox/system/testing/BaseTestCase.cfc" ) ).findNoCase( "runRouteMiddleware" ) > 0
		);
	}

	/**
	 * A stub user: id 1, permissions read + write, role editor
	 */
	private function buildUser(){
		return createStub()
			.$( "getId", 1 )
			.$(
				method   = "hasPermission",
				callback = function( permission ){
					var perms = isArray( arguments.permission ) ? arguments.permission : listToArray(
						arguments.permission
					);
					return perms
						.filter( function( item ){
							return listFindNoCase( "read,write", item ) > 0;
						} )
						.len() > 0;
				}
			)
			.$(
				method   = "hasRole",
				callback = function( role ){
					var roles = isArray( arguments.role ) ? arguments.role : listToArray( arguments.role );
					return roles
						.filter( function( item ){
							return item == "editor";
						} )
						.len() > 0;
				}
			);
	}

}
