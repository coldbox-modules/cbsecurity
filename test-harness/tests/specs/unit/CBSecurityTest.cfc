component extends="coldbox.system.testing.BaseModelTest" model="cbsecurity.models.CBSecurity"{

	/*********************************** LIFE CYCLE Methods ***********************************/

	// executes before all suites+specs in the run() method
	function beforeAll(){
		super.setup();
	}

	// executes after all suites+specs in the run() method
	function afterAll(){

	}

/*********************************** BDD SUITES ***********************************/

	function run( testResults, testBox ){
		// all your suites go here.
		describe( "CBSecurity Model", function(){

			beforeEach(function( currentSpec ){
				cbsecurity = model.init();

				mockAuthService = createStub();
				mockUser = createMock( "root.models.User" ).init();

				cbSecurity.$( "getAuthService", mockAuthService );

				mockAuthService.$( "getUser", mockUser );
			});

			it( "can be created", function(){
				expect( cbsecurity ).toBeComponent();
			});

			describe( "verification via has()", function(){
				it( "can verify true if the user has one permission" , function(){
					mockUser.$( "hasPermission", true );
					expect( cbsecurity.has( "test" ) ).toBeTrue();
				});
				it( "can verify false if the user has no permissions" , function(){
					mockUser.$( "hasPermission", false );
					expect( cbsecurity.has( "test" ) ).toBeFalse();
				});
				it( "can verify true if the user has one of many permission" , function(){
					mockUser.$( "hasPermission" ).$results( true, false, false, true );
					expect( cbsecurity.has( "test,test2,test3,test4" ) ).toBeTrue();
				});
			});

			describe( "verification via all()", function(){
				it( "can verify true if the user has one permission" , function(){
					mockUser.$( "hasPermission", true );
					expect( cbsecurity.all( "test" ) ).toBeTrue();
				});
				it( "can verify false if the user has no permissions" , function(){
					mockUser.$( "hasPermission", false );
					expect( cbsecurity.all( "test" ) ).toBeFalse();
				});
				it( "can verify false if the user has one of many permission only" , function(){
					mockUser.$( "hasPermission" ).$results( true, false, false, true );
					expect( cbsecurity.all( "test,test2,test3,test4" ) ).toBeFalse();
				});
			});

			describe( "verification via none()", function(){
				it( "can verify true if the user doesn't have one permission" , function(){
					mockUser.$( "hasPermission", false );
					expect( cbsecurity.none( "test" ) ).toBeTrue();
				});
				it( "can verify false if the user has a permission" , function(){
					mockUser.$( "hasPermission", true );
					expect( cbsecurity.none( "test" ) ).toBeFalse();
				});
				it( "can verify false if the user has one of many permission only" , function(){
					mockUser.$( "hasPermission" ).$results( true, false, false, false );
					expect( cbsecurity.none( "test,test2,test3,test4" ) ).toBeFalse();
				});
			});

			describe( "verification via sameUser()", function(){
				it( "can validate when passing the same user", function(){
					mockUser.$( "getId", 1 );
					var testUser = createStub().$( "getId", 1 );

					expect( cbSecurity.sameUser( testUser ) ).toBeTrue();
				});

				it( "can invalidate when passing a different user", function(){
					mockUser.$( "getId", 1 );
					var testUser = createStub().$( "getId", 1333 );

					expect( cbSecurity.sameUser( testUser ) ).toBeFalse();
				});
			});

			describe( "blocking methods", function(){
				describe( "secure() method", function(){
					it( "can allow a secure() function if permissions pass", function(){
						mockUser.$( "hasPermission", true );
						cbsecurity.secure( "test" );
					});
					it( "can block a secure() call with invalid permissions", function(){
						mockUser.$( "hasPermission", false );
						expect( function(){
							cbsecurity.secure( "test" );
						}).toThrow( "NotAuthorized" );
					});
					it( "can block a secure() call with a custom message", function(){
						mockUser.$( "hasPermission", false );
						expect( function(){
							cbsecurity.secure( "test", "Invalid User Baby" );
						}).toThrow( type="NotAuthorized", regex="Invalid User Baby" );
					});
				});
				describe( "secureAll() method", function(){
					it( "can allow a secureAll() function if all permissions pass", function(){
						mockUser.$( "hasPermission" ).$results( true, true );
						cbsecurity.secureAll( "test,test2" );
					});
					it( "can block a secureAll() call with invalid permissions", function(){
						mockUser.$( "hasPermission" ).$results( false, true, false );
						expect( function(){
							cbsecurity.secureAll( "test,test2,test3" );
						}).toThrow( "NotAuthorized" );
					});
					it( "can block a secureAll() call with a custom message", function(){
						mockUser.$( "hasPermission", false );
						expect( function(){
							cbsecurity.secureAll( "test", "Invalid User Baby" );
						}).toThrow( type="NotAuthorized", regex="Invalid User Baby" );
					});
				});
				describe( "secureNone() method", function(){
					it( "can allow a secureNone() function if all permissions are not found", function(){
						mockUser.$( "hasPermission" ).$results( false, false );;
						cbsecurity.secureNone( "test,test2" );
					});
					it( "can block a secureNone() call with found permissions", function(){
						mockUser.$( "hasPermission" ).$results( false, true, false );
						expect( function(){
							cbsecurity.secureNone( "test,test2,test3" );
						}).toThrow( "NotAuthorized" );
					});
					it( "can block a secureNone() call with a custom message", function(){
						mockUser.$( "hasPermission", true );
						expect( function(){
							cbsecurity.secureNone( "test", "Invalid User Baby" );
						}).toThrow( type="NotAuthorized", regex="Invalid User Baby" );
					});
				});

				describe( "secureWhen() method", function(){
					it( "can secure if a boolean true is passed", function(){
						expect( function(){
							cbsecurity.secureWhen( true );
						}).toThrow( "NotAuthorized" );
					});
					it( "can allow if a boolean false is passed", function(){
						cbsecurity.secureWhen( false );
					});

					it( "can secure if a closure executes as true", function(){
						expect( function(){
							cbsecurity.secureWhen( function( user ){ return true; } );
						}).toThrow( "NotAuthorized" );
					});
					it( "can allow if a closure executes as false", function(){
						cbsecurity.secureWhen( function( user ){ return false; } );
					});

				});
			});

		});
	}

}