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
			beforeEach( function( currentSpec ){
				// Setup as a new ColdBox request for this suite, VERY IMPORTANT. ELSE EVERYTHING LOOKS LIKE THE SAME REQUEST.
				setup();
				// Get the Service
				variables.jwtService  = getInstance( "jwtService@cbSecurity" );
				variables.userService = getInstance( "UserService" );
			} );

			feature( "CBSecurity refresh tokens", function(){
				beforeEach( function( currentSpec ){
					variables.jwtService.getSettings().jwt.enableRefreshTokens = true;
				} );
				afterEach( function( currentSpec ){
					variables.jwtService.getSettings().jwt.enableRefreshTokens = false;
				} );

				story( "I can refresh tokens via the /refreshtoken endpoint", function(){
					given( "The endpoint is disabled", function(){
						then( "it should 404 a response", function(){
							variables.jwtService.getSettings().jwt.enableRefreshEndpoint = false;
							var event = this.post( "/cbsecurity/refreshtoken" );
							expect( event.getResponse().getStatusCode() ).toBe(
								404,
								event.getResponse().getMessagesString()
							);
						} );
					} );
					given( "An activated endpoint but no refresh tokens passed", function(){
						then( "it should 400 a response", function(){
							variables.jwtService.getSettings().jwt.enableRefreshEndpoint = true;
							var event = this.post( "/cbsecurity/refreshtoken" );
							expect( event.getResponse().getStatusCode() ).toBe(
								400,
								event.getResponse().getMessagesString()
							);
						} );
					} );
					given( "An activated endpoint and a valid refresh token", function(){
						then( "it should 200 a response with new refresh tokens", function(){
							var oUser  = variables.userService.retrieveUserByUsername( "test" );
							var tokens = variables.jwtService.fromUser( oUser );
							variables.jwtService.getSettings().jwt.enableRefreshEndpoint = true;

							var event = this.post(
								"/cbsecurity/refreshtoken",
								{ "x-refresh-token" : tokens.refresh_token }
							);
							expect( event.getResponse().getStatusCode() ).toBe(
								200,
								event.getResponse().getMessagesString()
							);
							expect( event.getResponse().getData() )
								.toBeStruct()
								.toHaveKey( "access_token" )
								.toHaveKey( "refresh_token" );
						} );
					} );
					given( "An activated endpoint and an invalid refresh token", function(){
						then( "it should kick me out", function(){
							variables.jwtService.getSettings().jwt.enableRefreshEndpoint = true;
							var event = this.post(
								"/cbsecurity/refreshtoken",
								{
									"x-refresh-token" : "eyJ0eXAiOiJKV1QihbGciOiJIUzUxMiJ9.eyJpYXQiOjE1Njg5MDMyODIsImlzcyI6Imh0dHA6Ly8xMjcuMC4wLjE6NTY1OTYvaW5kZXguY2ZtLyIsInN1YiI6MCwiZXhwIjoxNTY4OTA2ODgyLCJqdGkiOiIzRDUyMjUzNDM3Mjk4NjlCQkUzMjQxRUEzNjVEMUJDMyJ9.aCJrcD4TV0ei9lGpmrn0I2WQLrvSUx64BXPJYVi7BzZ2U-yS5ejg"
								}
							);
							expect( event.getResponse().getStatusCode() ).toBe(
								401,
								event.getResponse().getMessagesString()
							);
						} );
					} );
				} );

				it( "can generate both access and refresh tokens with a valid user", function(){
					var oUser  = variables.userService.retrieveUserByUsername( "test" );
					var tokens = variables.jwtService.fromUser( oUser );
					expect( tokens )
						.toBeStruct()
						.toHaveKey( "access_token" )
						.toHaveKey( "refresh_token" );
				} );

				it( "can discover refresh tokens via the rc", function(){
					var token = "eyJ0eXAiOiJKV1QihbGciOiJIUzUxMiJ9.eyJpYXQiOjE1Njg5MDMyODIsImlzcyI6Imh0dHA6Ly8xMjcuMC4wLjE6NTY1OTYvaW5kZXguY2ZtLyIsInN1YiI6MCwiZXhwIjoxNTY4OTA2ODgyLCJqdGkiOiIzRDUyMjUzNDM3Mjk4NjlCQkUzMjQxRUEzNjVEMUJDMyJ9.aCJrcD4TV0ei9lGpmrn0I2WQLrvSUx64BXPJYVi7BzZ2U-yS5ejg";
					getRequestContext().setValue( "x-refresh-token", token );
					makePublic( variables.jwtService, "discoverRefreshToken" );
					expect( variables.jwtService.discoverRefreshToken() ).toBe( token );
				} );

				it( "can discover refresh tokens and produce an empty result when none passed", function(){
					getRequestContext().setValue( "x-refresh-token", "" );
					makePublic( variables.jwtService, "discoverRefreshToken" );
					expect( variables.jwtService.discoverRefreshToken() ).toBeEmpty();
				} );

				it( "can refresh tokens via the refreshToken() method", function(){
					var oUser  = variables.userService.retrieveUserByUsername( "test" );
					var tokens = variables.jwtService.fromUser( oUser );

					var newTokens = variables.jwtService.refreshToken( tokens.refresh_token );
					expect( newTokens )
						.toBeStruct()
						.toHaveKey( "access_token" )
						.toHaveKey( "refresh_token" );
					expect( variables.jwtService.isTokenInStorage( tokens.refresh_token ) ).toBeFalse();
				} );
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

			given( "a valid jwt token with no required claims and accessing a secure api call", function(){
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

			given( "a valid jwt token that's expired", function(){
				then( "it should block with no authorization", function(){
					getRequestContext().setValue(
						"x-auth-token",
						"eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzUxMiJ9.eyJpYXQiOjE1NjkyNzI0NjQsInJvbGUiOiJhZG1pbiIsInNjb3BlcyI6W10sImlzcyI6Imh0dHA6Ly8xMjcuMC4wLjE6NTY1OTYvIiwic3ViIjoxMjMsImV4cCI6MTU2OTI3MjQ2NSwianRpIjoiRTRDNEM3MDdFNjA1MzQwRDkxRDNCMDBCMkI4NTdFNDMifQ.N2rT_b_Xp8e9Hw0O7yVork6Fg8aC7RKf0Fv-Bmu7Iv5CVvFrmk1gkF_oKeXmcl22MiwhB2oQJhMNZiFa5OfSKw"
					);
					var event = execute( route = "/api/secure", renderResults = true );
					expect( event.getCurrentEvent() ).toBe( "api:Home.onInvalidAuth" );
					expect( event.valueExists( "relocate_event" ) ).toBeFalse();
					expect( event.getPrivateValue( "cbsecurity_validatorResults" ).messages ).toInclude(
						"Token has expired"
					);
				} );
			} );

			given( "a valid jwt token but it is not in the storage", function(){
				then( "it should block with no authorization", function(){
					var thisToken = variables.jwtService.attempt( "test", "test" );

					variables.jwtService.getTokenStorage().clearAll();
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

					variables.jwtService
						.getTokenStorage()
						.set(
							key        = thisToken.payload.jti,
							token      = thisToken.token,
							expiration = 2,
							payload    = thisToken.payload
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
					var thisToken = variables.jwtService.attempt( "test", "test" );
					getRequestContext().setValue( "x-auth-token", thisToken );

					var event = execute( route = "/api/secure", renderResults = true );
					expect( event.getCurrentEvent() ).toBe( "api:secure.index" );
				} );
			} );

			story( "I want to invalidate all tokens in the storage", function(){
				given( "a valid jwt token and a invalidate all is issued", function(){
					then( "the storage should be empty", function(){
						var thisToken = variables.jwtService.attempt( "test", "test" );
						expect( variables.jwtService.getTokenStorage().size() ).toBeGT( 0 );

						variables.jwtService.invalidateAll();
						expect( variables.jwtService.getTokenStorage().size() ).toBe( 0 );
					} );
				} );
			} );
		} );
	}

	private function getInvalidUserToken(){
		var timestamp = now();
		var userId    = 123;
		var service   = variables.jwtService;
		var payload   = {
			// Issuing authority
			"iss"   : service.getSettings().jwt.issuer,
			// Token creation
			"iat"   : service.toEpoch( timestamp ),
			// The subject identifier
			"sub"   : 123,
			// The token expiration
			"exp"   : service.toEpoch( dateAdd( "n", 1, timestamp ) ),
			// The unique identifier of the token
			"jti"   : hash( timestamp & userId ),
			// Get the user scopes for the JWT token
			"scope" : [],
			"role"  : "admin"
		};

		return { "token" : service.encode( payload ), "payload" : payload };
	}

}
