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
component
	extends="coldbox.system.testing.BaseTestCase"
	appMapping="/root"
{

	/*********************************** LIFE CYCLE Methods ***********************************/

	function beforeAll(){
		structDelete( application, "cbController" );
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
			beforeEach( function(currentSpec){
				// Setup as a new ColdBox request for this suite, VERY IMPORTANT. ELSE EVERYTHING LOOKS LIKE THE SAME REQUEST.
				setup();
			} );

			it( "should load the rules from inline declaration", function(){
				var rules = getWireBox()
					.getInstance( "interceptor-cbsecurity@global" )
					.getProperty( "rules" );
				expect( rules ).notToBeEmpty();
			} );

			// direct action, use global redirect
			given( "a direct action of redirect with no explicit rule actions", function(){
				then( "it should do a global redirect using the global setting", function(){
					var event = execute( event = "admin.index", renderResults = true );
					// should have protected it
					expect( "main.index" ).toBe( event.getValue( "relocate_event" ) );
				} );
			} );

			// no action, use global default action
			given( "no direct action and no explicit rule actions", function(){
				then( "it should default to a redirect action to the global setting", function(){
					var event = execute( route = "/noAction", renderResults = true );
					expect( "main.index" ).toBe( event.getValue( "relocate_event" ) );
				} );
			} );

			// direct override action, use global override
			given( "a direct override action with no explicit rule actions", function(){
				then( "it should override using the global setting", function(){
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
					then( "it should redirect to the modules invalid access redirect setting", function(){
						var event = execute( event = "mod1:home", renderResults = true );

						debug( event.getPrivateCollection() );

						expect( "mod1/secure" ).toBe( event.getValue( "relocate_event" ) );
					} );
				} );

				given( "a module secured event with an override action", function(){
					then( "it should override to the modules invalid override event setting", function(){
						var event = execute( route = "/mod1/modOverride", renderResults = true );
						expect( event.getCurrentEvent() ).toBe( "mod1:secure.index" );
						expect( event.valueExists( "relocate_event" ) ).toBeFalse();
					} );
				} );

				given( "a module unload call", function(){
					then( "it should unload module rules if the module is unloaded", function(){
						var security = getWireBox().getInstance( "interceptor-cbsecurity@global" );
						var oldRules = security.getProperty( "rules" );

						// Issue unload
						getController().getModuleService().unload( "mod1" );

						// Verify
						expect( security.getSecurityModules() ).notToHaveKey( "mod1" );
						expect( security.getProperty( "rules" ).len() ).toBeLT( oldRules.len() );
					} );
				} );
			} );
		} );
	}

}
