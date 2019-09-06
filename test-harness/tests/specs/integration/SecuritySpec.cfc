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
		super.beforeAll();
		// do your own stuff here
	}

	function afterAll(){
		// do your own stuff here
		super.afterAll();
	}

	/*********************************** BDD SUITES ***********************************/

	function run(){
		describe( "Security module", function() {
			beforeEach( function(currentSpec) {
				// Setup as a new ColdBox request for this suite, VERY IMPORTANT. ELSE EVERYTHING LOOKS LIKE THE SAME REQUEST.
				setup();
			} );

			it( "should protect the admin and relocate", function() {
				var event = execute( event = "admin.index", renderResults = true );
				// should have protected it
				expect( "main.index" ).toBe( event.getValue( "relocate_event" ) );
			} );

			it( "should protect the admin and override", function(){
				var event = execute( route = "/override", renderResults = true );
				// should have protected it
				expect( event.getCurrentEvent() ).toBe( "main.index" );
				expect( event.valueExists( "relocate_event" ) ).toBeFalse();
			});
		} );
	}

}
