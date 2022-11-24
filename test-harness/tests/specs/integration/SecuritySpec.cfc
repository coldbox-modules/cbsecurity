/*******************************************************************************
 *	Integration Test as BDD (CF10+ or Railo 4.1 Plus)
 *
 *	Extends the integration class: coldbox.system.testing.BaseTestCase
 *
 *	so you can test your ColdBox application headlessly. The 'appMapping' points by default to
 *	the '/root' mapping created in the test folder Application.cfc.  Please note that this
 *	Application.cfc must mimic the real one in your root, including ORM settings if needed.
 *
 *	The 'execute()' method is used to execute a ColdBox event, with the following arguments
 *	* event : the name of the event
 *	* private : if the event is private or not
 *	* prePostExempt : if the event needs to be exempt of pre post interceptors
 *	* eventArguments : The struct of args to pass to the event
 *	* renderResults : Render back the results of the event
 *******************************************************************************/
component extends="coldbox.system.testing.BaseTestCase" appMapping="/root" {

	this.unloadColdbox = false;

	/*********************************** LIFE CYCLE Methods ***********************************/

	function beforeAll(){
		super.beforeAll();
		// do your own stuff here
	}

	function afterAll(){
		// do your own stuff here
		super.afterAll();
	}

	/*********************************** BDD SUITES ***********************************/

	function run(){
		describe( "Security module", function(){
			beforeEach( function( currentSpec ){
				// Setup as a new ColdBox request for this suite, VERY IMPORTANT. ELSE EVERYTHING LOOKS LIKE THE SAME REQUEST.
				setup();
				cbauth = getInstance( "authenticationService@cbauth" );
				cbauth.logout();
			} );

			describe( "Rule based Security", function(){
				it( "should load the rules from inline declaration", function(){
					var rules = getWireBox()
						.getInstance( "interceptor-cbsecurity@global" )
						.getProperty( "firewall" )
						.rules
						.inline;
					expect( rules ).notToBeEmpty();
				} );

				// direct action, use global redirect
				given( "a direct action of redirect with no explicit rule actions", function(){
					then( "it should do a global redirect using the global setting for invalid authentication", function(){
						var event = execute( event = "admin.index", renderResults = true );
						// should have protected it
						expect( "main.index" ).toBe( event.getValue( "relocate_event" ) );
					} );
				} );

				// match public with post|put
				given( "a secure event of public with a put,post http method constraint", function(){
					when( "when logged in and using a put or post", function(){
						then( "it should do allow it to be executed", function(){
							cbauth.authenticate( "test", "test" );
							var event = put( "putpost" );
							expect( "putpost" ).toBe( event.getRenderedContent() );
						} );
					} );
					when( "when logged in and using a GET", function(){
						then( "it should NOT allow it to be executed", function(){
							var event      = get( "putpost" );
							var renderData = event.getRenderData();
							expect( renderData.statusCode ).toBe( 401 );
							expect( renderData.data ).toInclude( "Unathorized" );
						} );
					} );
				} );

				// no action, use global default action
				given( "no direct action and no explicit rule actions", function(){
					then( "it should default to a redirect action to the global setting for invalid authentication", function(){
						var event = execute( route = "/noAction", renderResults = true );
						expect( "main.index" ).toBe( event.getValue( "relocate_event" ) );
					} );
				} );

				// direct override action, use global override
				given( "a direct override action with no explicit rule actions", function(){
					then( "it should override using the global setting for invalid authentication", function(){
						var event = execute( route = "/override", renderResults = true );
						expect( event.getCurrentEvent() ).toBe( "main.index" );
						expect( event.valueExists( "relocate_event" ) ).toBeFalse();
					} );
				} );

				// Using overrideEvent only, so use an explicit override
				given( "no direct action but using an overrideEvent rule action", function(){
					then( "it should override using the overrideEvent element", function(){
						var event = execute( route = "/ruleActionOverride", renderResults = true );
						expect( event.getCurrentEvent() ).toBe( "main.login" );
						expect( event.valueExists( "relocate_event" ) ).toBeFalse();
					} );
				} );

				// Using redirect only, so use an explicit redirect
				given( "no direct action but using a redirect rule action", function(){
					then( "it should redirect using the redirect element", function(){
						var event = execute( route = "/ruleActionRedirect", renderResults = true );
						expect( "main.login" ).toBe( event.getValue( "relocate_event" ) );
					} );
				} );

				describe( "Module cbsecurity integrations", function(){
					given( "a module secured event", function(){
						then( "it should redirect to the modules invalidAuthenticationEvent redirect setting", function(){
							var event = execute( event = "mod1:home", renderResults = true );
							debug( event.getPrivateCollection() );

							expect( event.getValue( "relocate_event" ) ).toBe( "mod1:secure.index" );
						} );
					} );

					given( "a module secured event with an override action", function(){
						then( "it should override to the modules invalidAuthenticationEvent", function(){
							var event = execute( route = "/mod1/modOverride", renderResults = true );
							expect( event.getCurrentEvent() ).toBe( "mod1:secure.index" );
							expect( event.valueExists( "relocate_event" ) ).toBeFalse();
						} );
					} );

					given( "a module unload call", function(){
						then( "it should unload module rules if the module is unloaded", function(){
							var security = getWireBox().getInstance( "interceptor-cbsecurity@global" );
							var oldRules = security.getProperty( "firewall" ).rules.inline;

							// Issue unload
							getController().getModuleService().unload( "mod1" );

							// Verify
							expect( security.getProperties().securityModules ).notToHaveKey( "mod1" );
							expect( security.getProperty( "firewall" ).rules.inline.len() ).toBeLT(
								oldRules.len()
							);
						} );
					} );
				} );
			} );

			describe( "Annotation based Security", function(){
				given( "a public handler and action", function(){
					then( "it should execute it", function(){
						var event = execute( event = "public.index", renderResults = true );
						expect( event.getRenderedContent() ).toInclude( "public" );
					} );
				} );

				given( "A secured annotated handler and a non-annotated action", function(){
					then( "it should block and redirect", function(){
						var event = execute( event = "Annotations.index", renderResults = true );
						expect( "main.index" ).toBe( event.getValue( "relocate_event" ) );
					} );
				} );

				given( "A secured annotated handler and an annotated action", function(){
					then( "it should block and redirect as well", function(){
						var event = execute( event = "Annotations.secret", renderResults = true );
						expect( "main.index" ).toBe( event.getValue( "relocate_event" ) );
					} );
				} );

				given( "A secured annotated handler and an annotated action and a valid access", function(){
					then( "it should allow access", function(){
						prepareMock( getInstance( "AuthValidator@cbSecurity" ) ).$(
							"annotationValidator",
							{ allow : true, type : "authentication" }
						);
						var event = execute( event = "Annotations.secret", renderResults = true );
						expect( event.getRenderedContent() ).toInclude( "Mega secured action" );
					} );
				} );

				given( "A secured annotated handler and an annotated action with invalid auth", function(){
					then( "it should allow access to handler but not to action", function(){
						prepareMock( getInstance( "AuthValidator@cbSecurity" ) )
							.$( "annotationValidator" )
							.$results(
								{ allow : true, type : "authentication" },
								{ allow : false, type : "authorization" }
							);
						var event = execute( event = "Annotations.secret", renderResults = true );
						expect( event.getValue( "relocate_event" ) ).toBe( "main.index" );
					} );
				} );
			} );
		} );
	}

}
