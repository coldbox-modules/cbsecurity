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

	this.unloadColdBox = false;

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
		describe( "CBSecurity Basic Auth User Service", function(){
			beforeEach( function( currentSpec ){
				// Setup as a new ColdBox request for this suite, VERY IMPORTANT. ELSE EVERYTHING LOOKS LIKE THE SAME REQUEST.
				setup();
				userService = getInstance( "BasicAuthUserService@cbsecurity" );
			} );

			it( "can be created and user storage configured", function(){
				expect( userService ).toBeComponent();
				var users = userService.getSettings().basicAuth.users;
				expect( users ).notToBeEmpty();
				// Verify normalization
				users.each( ( k, v ) => {
					expect( v ).toHaveKey( "id,username,password,permissions,roles" );
				} );
			} );

			it( "can dispense new users", function(){
				expect( userService.new().isLoaded() ).toBeFalse();
			} );

			it( "can retrieve a valid user by id", function(){
				var target = userService.getSettings().basicAuth.users[ "test" ];
				expect( userService.retrieveUserById( target.id ).isLoaded() ).toBeTrue();
			} );

			it( "can retrieve an invalid user by id", function(){
				expect( userService.retrieveUserById( 1234 ).isLoaded() ).toBeFalse();
			} );

			it( "can retrieve a valid user by username", function(){
				expect( userService.retrieveUserByUsername( "lmajano" ).isLoaded() ).toBeTrue();
			} );

			it( "can retrieve an invalid user by username", function(){
				expect( userService.retrieveUserByUsername( "bogus" ).isLoaded() ).toBeFalse();
			} );

			it( "can validate valid user credentials", function(){
				expect( userService.isValidCredentials( "lmajano", "test" ) ).toBeTrue();
			} );

			it( "can invalidate invalid user credentials", function(){
				expect( userService.isValidCredentials( "bogus", "test" ) ).toBeFalse();
			} );
		} );
	}

}
