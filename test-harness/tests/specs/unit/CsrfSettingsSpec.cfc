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
			} );

			it( "leaves the cbcsrf settings alone when cbsecurity.csrf sets nothing", function(){
				var cbcsrf             = duplicate( defaults );
				cbcsrf.rotationTimeout = 99;
				cbcsrf.enableEndpoint  = true;

				var resolved = model.resolveCsrfSettings( {}, cbcsrf );

				expect( resolved.rotationTimeout ).toBe( 99 );
				expect( resolved.enableEndpoint ).toBeTrue();
			} );

			it( "applies the keys the user set in cbsecurity.csrf over the defaults", function(){
				var resolved = model.resolveCsrfSettings( { rotationTimeout : 77 }, duplicate( defaults ) );

				expect( resolved.rotationTimeout ).toBe( 77 );
				expect( resolved.enableEndpoint ).toBeFalse();
			} );

			it( "lets an explicit cbsecurity.csrf key win over a cbcsrf override", function(){
				var cbcsrf             = duplicate( defaults );
				cbcsrf.rotationTimeout = 99;

				var resolved = model.resolveCsrfSettings( { rotationTimeout : 77 }, cbcsrf );

				expect( resolved.rotationTimeout ).toBe( 77 );
			} );

			it( "keeps cbcsrf overrides for keys cbsecurity did not set", function(){
				var cbcsrf             = duplicate( defaults );
				cbcsrf.rotationTimeout = 99;
				cbcsrf.enableEndpoint  = true;

				var resolved = model.resolveCsrfSettings( { rotationTimeout : 77 }, cbcsrf );

				expect( resolved.rotationTimeout ).toBe( 77 );
				expect( resolved.enableEndpoint ).toBeTrue();
			} );

			it( "applies complex values from cbsecurity.csrf", function(){
				var cbcsrf            = duplicate( defaults );
				cbcsrf.verifyExcludes = [ "stripe" ];

				var resolved = model.resolveCsrfSettings( { verifyExcludes : [ "other" ] }, cbcsrf );

				expect( resolved.verifyExcludes ).toBe( [ "other" ] );
			} );

			it( "does not change the settings it is given", function(){
				var cbcsrf = duplicate( defaults );
				model.resolveCsrfSettings( { rotationTimeout : 77 }, cbcsrf );
				expect( cbcsrf.rotationTimeout ).toBe( 30 );
			} );
		} );
	}

}
