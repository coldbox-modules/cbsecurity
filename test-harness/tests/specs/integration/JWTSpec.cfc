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
		describe( "JWT Security Services", function(){

			beforeEach( function(currentSpec){
				// Setup as a new ColdBox request for this suite, VERY IMPORTANT. ELSE EVERYTHING LOOKS LIKE THE SAME REQUEST.
				setup();
			} );

			given( "no jwt token and accessing a secure api call", function(){
				then( "it should block with no authorization", function(){
					var event = execute( route = "/api/secure", renderResults = true );
					expect( event.getCurrentEvent() ).toBe( "api:Home.onInvalidAuth" );
					expect( event.valueExists( "relocate_event" ) ).toBeFalse();
				});
			});

		} );
	}

}
