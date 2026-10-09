/**
 * Which settings win between the cbsecurity `csrf` key and the cbcsrf module settings
 */
component extends="coldbox.system.testing.BaseModelTest" model="cbsecurity.models.CBSecurity" {

	function beforeAll(){
		super.beforeAll();
		// The defaults that both modules share
		variables.defaults = {
			enableAutoVerifier     : false,
			verifyExcludes         : [],
			rotationTimeout        : 30,
			enableEndpoint         : false,
			cacheStorage           : "CacheStorage@cbstorages",
			enableAuthTokenRotator : true
		};
	}

	function run(){
		describe( "cbcsrf settings precedence", function(){
			beforeEach( function(){
				setup();
				model.$property(
					"DEFAULT_SETTINGS",
					"variables",
					{ csrf : duplicate( defaults ) }
				);
			} );

			it( "leaves the cbcsrf settings alone when cbsecurity.csrf sets nothing", function(){
				var cbcsrf             = duplicate( defaults );
				cbcsrf.rotationTimeout = 99;
				cbcsrf.enableEndpoint  = true;

				var resolved = model.resolveCsrfSettings( {}, cbcsrf );

				expect( resolved.rotationTimeout ).toBe( 99 );
				expect( resolved.enableEndpoint ).toBeTrue();
			} );

			it( "applies the keys the user set in cbsecurity.csrf", function(){
				var resolved = model.resolveCsrfSettings( { rotationTimeout : 77 }, duplicate( defaults ) );

				expect( resolved.rotationTimeout ).toBe( 77 );
				expect( resolved.enableEndpoint ).toBeFalse();
			} );

			it( "lets an explicit cbcsrf setting win over cbsecurity.csrf", function(){
				var cbcsrf             = duplicate( defaults );
				cbcsrf.rotationTimeout = 99;

				var resolved = model.resolveCsrfSettings(
					{ rotationTimeout : 77 },
					cbcsrf,
					[ "rotationTimeout" ]
				);

				expect( resolved.rotationTimeout ).toBe( 99 );
			} );

			it( "matches the explicit cbcsrf keys without regard to case", function(){
				var cbcsrf             = duplicate( defaults );
				cbcsrf.rotationTimeout = 99;

				var resolved = model.resolveCsrfSettings(
					{ rotationTimeout : 77 },
					cbcsrf,
					[ "ROTATIONTIMEOUT" ]
				);

				expect( resolved.rotationTimeout ).toBe( 99 );
			} );

			it( "lets a cbcsrf value that is not the default win even if it was set outside the app config", function(){
				// For example from config/modules/cbcsrf.cfc
				var cbcsrf             = duplicate( defaults );
				cbcsrf.rotationTimeout = 99;

				var resolved = model.resolveCsrfSettings( { rotationTimeout : 77 }, cbcsrf );

				expect( resolved.rotationTimeout ).toBe( 99 );
			} );

			it( "mixes the two modules key by key", function(){
				var cbcsrf             = duplicate( defaults );
				cbcsrf.rotationTimeout = 99;

				var resolved = model.resolveCsrfSettings(
					{ rotationTimeout : 77, enableEndpoint : true },
					cbcsrf,
					[ "rotationTimeout" ]
				);

				// cbcsrf wins where it was set, cbsecurity fills in the rest
				expect( resolved.rotationTimeout ).toBe( 99 );
				expect( resolved.enableEndpoint ).toBeTrue();
			} );

			it( "compares complex values to find out if they are still the default", function(){
				var cbcsrf            = duplicate( defaults );
				cbcsrf.verifyExcludes = [ "stripe" ];

				var resolved = model.resolveCsrfSettings( { verifyExcludes : [ "other" ] }, cbcsrf );
				expect( resolved.verifyExcludes ).toBe( [ "stripe" ] );

				// An untouched empty array is still the default, so cbsecurity can set it
				var fresh = model.resolveCsrfSettings( { verifyExcludes : [ "other" ] }, duplicate( defaults ) );
				expect( fresh.verifyExcludes ).toBe( [ "other" ] );
			} );

			it( "does not change the settings it is given", function(){
				var cbcsrf = duplicate( defaults );
				model.resolveCsrfSettings( { rotationTimeout : 77 }, cbcsrf );
				expect( cbcsrf.rotationTimeout ).toBe( 30 );
			} );
		} );
	}

}
