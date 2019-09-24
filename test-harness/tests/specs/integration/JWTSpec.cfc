component extends="coldbox.system.testing.BaseTestCase" appMapping="/root" {

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
				} );
			} );

			given( "an empty jwt token and accessing a secure api call", function(){
				then( "it should block with no authorization", function(){
					getRequestContext().setValue( "x-auth-token", "" );
					var event = execute( route = "/api/secure", renderResults = true );
					expect( event.getCurrentEvent() ).toBe( "api:Home.onInvalidAuth" );
					expect( event.valueExists( "relocate_event" ) ).toBeFalse();
					expect( event.getPrivateValue( "cbsecurity_validatorResults" ).messages ).toInclude(
						"TokenNotFoundException"
					);
				} );
			} );

			given( "an invalid jwt token and accessing a secure api call", function(){
				then( "it should block with no authorization", function(){
					getRequestContext().setValue(
						"x-auth-token",
						"eyJ0eXAiOiJKV1QihbGciOiJIUzUxMiJ9.eyJpYXQiOjE1Njg5MDMyODIsImlzcyI6Imh0dHA6Ly8xMjcuMC4wLjE6NTY1OTYvaW5kZXguY2ZtLyIsInN1YiI6MCwiZXhwIjoxNTY4OTA2ODgyLCJqdGkiOiIzRDUyMjUzNDM3Mjk4NjlCQkUzMjQxRUEzNjVEMUJDMyJ9.aCJrcD4TV0ei9lGpmrn0I2WQLrvSUx64BXPJYVi7BzZ2U-yS5ejg"
					);
					var event = execute( route = "/api/secure", renderResults = true );
					expect( event.getCurrentEvent() ).toBe( "api:Home.onInvalidAuth" );
					expect( event.valueExists( "relocate_event" ) ).toBeFalse();
					expect( event.getPrivateValue( "cbsecurity_validatorResults" ).messages ).toInclude(
						"TokenInvalidException"
					);
				} );
			} );

			given( "an valid jwt token with no required claims and accessing a secure api call", function(){
				then( "it should block with no authorization", function(){
					getRequestContext().setValue(
						"x-auth-token",
						"eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzUxMiJ9.eyJpYXQiOjE1NjkyNzIwOTksInNjb3BlcyI6W10sImlzcyI6Imh0dHA6Ly8xMjcuMC4wLjE6NTY1OTYvIiwic3ViIjoxMjMsImV4cCI6MTU2OTI3MjEwMCwianRpIjoiMTkzQ0NFNUIwNjRENUJEMERENjcxRTQ4N0EzNzI3Q0QifQ.QovEexPi5BCca_N_LHv9R2dUF-GOHbUKOSIzRT7udsHL0zGkkzkVeVPR1_ccxciGoJL_IZaI0AG9_gHKk2Yf9g"
					);
					var event = execute( route = "/api/secure", renderResults = true );
					expect( event.getCurrentEvent() ).toBe( "api:Home.onInvalidAuth" );
					expect( event.valueExists( "relocate_event" ) ).toBeFalse();
					expect( event.getPrivateValue( "cbsecurity_validatorResults" ).messages ).toInclude(
						"TokenInvalidException"
					);
				} );
			} );

			given( "an valid jwt token that's expired", function(){
				then( "it should block with no authorization", function(){
					getRequestContext().setValue(
						"x-auth-token",
						"eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzUxMiJ9.eyJpYXQiOjE1NjkyNzI0NjQsInJvbGUiOiJhZG1pbiIsInNjb3BlcyI6W10sImlzcyI6Imh0dHA6Ly8xMjcuMC4wLjE6NTY1OTYvIiwic3ViIjoxMjMsImV4cCI6MTU2OTI3MjQ2NSwianRpIjoiRTRDNEM3MDdFNjA1MzQwRDkxRDNCMDBCMkI4NTdFNDMifQ.N2rT_b_Xp8e9Hw0O7yVork6Fg8aC7RKf0Fv-Bmu7Iv5CVvFrmk1gkF_oKeXmcl22MiwhB2oQJhMNZiFa5OfSKw"
					);
					var event = execute( route = "/api/secure", renderResults = true );
					expect( event.getCurrentEvent() ).toBe( "api:Home.onInvalidAuth" );
					expect( event.valueExists( "relocate_event" ) ).toBeFalse();
					expect( event.getPrivateValue( "cbsecurity_validatorResults" ).messages ).toInclude(
						"TokenExpiredException"
					);
				} );
			} );

			given( "an valid jwt token but it is not in the storage", function(){
				then( "it should block with no authorization", function(){
					var thisToken = getInstance( "jwtService@cbSecurity" ).attempt( "test", "test" );

					getInstance( "jwtService@cbSecurity" )
						.getTokenStorage()
						.clearAll();
					getRequestContext().setValue( "x-auth-token", thisToken );
					var event = execute( route = "/api/secure", renderResults = true );

					expect( event.getCurrentEvent() ).toBe( "api:Home.onInvalidAuth" );
					expect( event.valueExists( "relocate_event" ) ).toBeFalse();
					expect( event.getPrivateValue( "cbsecurity_validatorResults" ).messages ).toInclude(
						"TokenRejectionException"
					);
				} );
			} );

			given( "an valid jwt token but with an invalid user", function(){
				then( "it should block with no authorization", function(){
					var thisToken = getInvalidUserToken();
					getRequestContext().setValue( "x-auth-token", thisToken.token );

					getInstance( "jwtService@cbSecurity" )
						.getTokenStorage()
						.set(
							key 		= thisToken.payload.jti,
							token 		= thisToken.token,
							expiration 	= 2,
							payload		= thisToken.payload
						);
					var event = execute( route = "/api/secure", renderResults = true );

					expect( event.getCurrentEvent() ).toBe( "api:Home.onInvalidAuth" );
					expect( event.valueExists( "relocate_event" ) ).toBeFalse();
					expect( event.getPrivateValue( "cbsecurity_validatorResults" ).messages ).toInclude(
						"InvalidTokenUser"
					);
				} );
			} );

			given( "a valid jwt token in all senses", function(){
				then( "it should allow the call", function(){
					var thisToken = getInstance( "jwtService@cbSecurity" ).attempt( "test", "test" );
					getRequestContext().setValue( "x-auth-token", thisToken );

					var event = execute( route = "/api/secure", renderResults = true );
					expect( event.getCurrentEvent() ).toBe( "api:secure.index" );
				} );
			} );
		} );
	}

	private function getInvalidUserToken(){
		var timestamp = now();
		var userId    = 123;
		var service   = getInstance( "jwtService@cbsecurity" );
		var payload   = {
			// Issuing authority
			"iss"    : getRequestContext().getHTMLBaseURL(),
			// Token creation
			"iat"    : service.toEpoch( timestamp ),
			// The subject identifier
			"sub"    : 123,
			// The token expiration
			"exp"    : service.toEpoch( dateAdd( "n", 1, timestamp ) ),
			// The unique identifier of the token
			"jti"    : hash( timestamp & userId ),
			// Get the user scopes for the JWT token
			"scopes" : [],
			"role"   : "admin"
		};

		return { "token" : service.encode( payload ), "payload" : payload };
	}

}
