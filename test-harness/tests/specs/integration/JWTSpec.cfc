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

			given( "an empty jwt token and accessing a secure api call", function(){
				then( "it should block with no authorization", function(){
					getRequestContext().setValue( "x-auth-token", "" );
					var event = execute( route = "/api/secure", renderResults = true );
					expect( event.getCurrentEvent() ).toBe( "api:Home.onInvalidAuth" );
					expect( event.valueExists( "relocate_event" ) ).toBeFalse();
				});
			});

			given( "an invalid jwt token w and accessing a secure api call", function(){
				then( "it should block with no authorization", function(){
					getRequestContext().setValue( "x-auth-token", "eyJ0eXAiOiJKV1QihbGciOiJIUzUxMiJ9.eyJpYXQiOjE1Njg5MDMyODIsImlzcyI6Imh0dHA6Ly8xMjcuMC4wLjE6NTY1OTYvaW5kZXguY2ZtLyIsInN1YiI6MCwiZXhwIjoxNTY4OTA2ODgyLCJqdGkiOiIzRDUyMjUzNDM3Mjk4NjlCQkUzMjQxRUEzNjVEMUJDMyJ9.aCJrcD4TV0ei9lGpmrn0I2WQLrvSUx64BXPJYVi7BzZ2U-yS5ejg" );
					var event = execute( route = "/api/secure", renderResults = true );
					expect( event.getCurrentEvent() ).toBe( "api:Home.onInvalidAuth" );
					expect( event.valueExists( "relocate_event" ) ).toBeFalse();
				});
			});

			given( "an valid jwt token with no required claims and accessing a secure api call", function(){
				then( "it should block with no authorization", function(){
					getRequestContext().setValue( "x-auth-token", "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzUxMiJ9.eyJpYXQiOjE1Njg5MDMyODIsImlzcyI6Imh0dHA6Ly8xMjcuMC4wLjE6NTY1OTYvaW5kZXguY2ZtLyIsInN1YiI6MCwiZXhwIjoxNTY4OTA2ODgyLCJqdGkiOiIzRDUyMjUzNDM3Mjk4NjlCQkUzMjQxRUEzNjVEMUJDMyJ9.aCJrcD4TV0ei9lGpmrn0I2WQLrvSUx64BXP57oi0UyS0T90WyXU2OMQsQbdxg7mnPyP2NJYVi7BzZ2U-yS5ejg" );
					var event = execute( route = "/api/secure", renderResults = true );
					expect( event.getCurrentEvent() ).toBe( "api:Home.onInvalidAuth" );
					expect( event.valueExists( "relocate_event" ) ).toBeFalse();
				});
			});

		} );
	}

}
