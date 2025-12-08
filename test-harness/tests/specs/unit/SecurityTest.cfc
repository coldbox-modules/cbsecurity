component extends="coldbox.system.testing.BaseInterceptorTest" interceptor="cbsecurity.interceptors.Security" {

	function beforeAll(){
		super.beforeAll();
	}

	/*********************************** BDD SUITES ***********************************/

	function run( testResults, testBox ){
		// all your suites go here.
		describe( "Security Interceptor Unit Tests", function(){
			beforeEach( function( currentSpec ){
				// setup properties
				setup();

				mockWireBox = new coldbox.system.ioc.Injector( "tests.resources.Binder" );

				mockController
					.$( "getAppHash", hash( "appHash" ) )
					.$( "getAppRootPath", expandPath( "/root" ) )
					.$(
						"getColdboxSettings",
						{ "version" : "6.0.0" },
						false
					);
				mockLogger = createEmptyMock( "coldbox.system.logging.Logger" ).$( "info" ).$( "warn" )
				mockController
					.$( "getSetting" )
					.$args( "modules" )
					.$results( [] );

				mockSecurityService = prepareMock( new cbsecurity.models.CBSecurity() );

				security = interceptor;
				settings = {
					visualizer : { enabled : false },
					firewall   : {
						// The global invalid authentication event or URI or URL to go if an invalid authentication occurs
						"invalidAuthenticationEvent"  : "",
						// Default Auhtentication Action: override or redirect when a user has not logged in
						"defaultAuthenticationAction" : "redirect",
						// The global invalid authorization event or URI or URL to go if an invalid authorization occurs
						"invalidAuthorizationEvent"   : "",
						// Default invalid action: override or redirect when an invalid access is detected, default is to redirect
						"defaultAuthorizationAction"  : "redirect",
						// The rule validator model, this must have a method like this `userValidator( rule, controller ):boolean`
						"validator"                   : "tests.resources.security",
						// Auto load the global security firewall
						"autoLoadFirewall"            : true,
						// Activate handler/action based annotation security
						"handlerAnnotationSecurity"   : true,
						"rules"                       : {
							// Use regular expression matching on the rules
							"useRegex" : true,
							// Force SSL for all relocations
							"useSSL"   : false,
							"inline"   : [],
							"provider" : { source : "", properties : {} },
							"defaults" : {}
						}
					}
				};

				// Prepare for testing
				security
					.$property( "log", "variables", mockLogger )
					.setCBSecurity( mockSecurityService )
					.setInvalidEventHandler( "" )
					.setRulesLoader( createRuleLoader() )
					.setProperties( settings );
			} );

			it( "can configure with default settings", function(){
				security.configure();
				expect( security.getProperty( "firewall" ).rules.inline ).toBeEmpty();
				expect( security.getProperty( "firewall" ).validator ).toBe( "tests.resources.security" );
			} );

			it( "can configure with invalid settings and throw exceptions", function(){
				settings.firewall.rules.provider.source = "json";
				expect( function(){
					security.configure();
				} ).toThrow( "Security.MissingSourceProperty" );

				settings.firewall.rules.provider.source = "hello";
				expect( function(){
					security.configure();
				} ).toThrow( "Security.InvalidRuleSource" );

				settings.firewall.rules.provider.source = "db";
				expect( function(){
					security.configure();
				} ).toThrow( "Security.MissingSourceProperty" );

				settings.firewall.rules.provider.source = "model";
				expect( function(){
					security.configure();
				} ).toThrow( "Security.MissingSourceProperty" );
			} );

			it( "can load a valid validator", function(){
				settings.firewall.rules.provider.source          = "json";
				settings.firewall.rules.provider.properties.file = expandPath(
					"/tests/resources/security.json.cfm"
				);
				settings.firewall.validator = "tests.resources.security";
				mockValidator               = mockWireBox.getInstance( settings.firewall.validator );
				security.getRulesLoader().$( "loadRules", [] );

				security
					.$( "getInstance" )
					.$args( settings.firewall.validator )
					.$results( mockValidator );

				security.afterAspectsLoad();

				expect(
					security.getValidator(
						createMock( "coldbox.system.web.context.RequestContext" ).$( "getCurrentModule", "" )
					)
				).toBeComponent();
			} );

			it( "can detect an invalid validator", function(){
				settings.firewall.rules.provider.source          = "json";
				settings.firewall.rules.provider.properties.file = expandPath(
					"/tests/resources/security.json.cfm"
				);
				settings.firewall.validator = "tests.invalidty";
				security.getRulesLoader().$( "loadRules", [] );

				security
					.$( "getInstance" )
					.$args( settings.firewall.validator )
					.$results( createStub() );

				expect( function(){
					security.afterAspectsLoad();
				} ).toThrow( "Security.ValidatorMethodException" );
			} );

			it( "does not enable invalid event handler processing on Coldbox versions 6+", function(){
				security.setProperties( settings );
				mockValidator = mockWireBox.getInstance( settings.firewall.validator );
				security
					.$( "getInstance" )
					.$args( settings.firewall.validator )
					.$results( mockValidator );
				security.configure();
				expect( security.$getProperty( "enableInvalidHandlerCheck" ) ).toBeFalse();
			} );

			it( "enables invalid event handler processing on Coldbox versions prior to 6", function(){
				mockController.$(
					"getColdboxSettings",
					{ "version" : "5.0.0" },
					false
				);
				mockValidator = mockWireBox.getInstance( settings.firewall.validator );
				security
					.$( "getInstance" )
					.$args( settings.firewall.validator )
					.$results( mockValidator );
				security.configure();
				expect( security.$getProperty( "enableInvalidHandlerCheck" ) ).toBeTrue();
			} );

			describe( "It can load many types of rules", function(){
				beforeEach( function( currentSpec ){
					settings.firewall.validator = "tests.resources.security";
					mockValidator               = mockWireBox.getInstance( settings.firewall.validator );
					security
						.$( "getInstance" )
						.$args( settings.firewall.validator )
						.$results( mockValidator );
				} );

				it( "can load JSON Rules", function(){
					settings.firewall.rules.provider.source          = "json";
					settings.firewall.rules.provider.properties.file = expandPath(
						"/tests/resources/security.json.cfm"
					);
					mockController.$( "locateFilePath", settings.firewall.rules.provider.properties.file );

					security.configure();

					expect( security.getProperty( "firewall" ).rules.inline ).toHaveLength( 2 );
				} );

				it( "can load XML Rules", function(){
					settings.firewall.rules.provider.source          = "xml";
					settings.firewall.rules.provider.properties.file = expandPath(
						"/tests/resources/security.xml.cfm"
					);
					mockController.$( "locateFilePath", settings.firewall.rules.provider.properties.file );

					security.configure();

					expect( security.getProperty( "firewall" ).rules.inline ).toHaveLength( 3 );
				} );

				it( "can load model Rules", function(){
					settings.firewall.rules.provider.source           = "model";
					settings.firewall.rules.provider.properties.model = "tests.resources.security";

					security.configure();

					expect( security.getProperty( "firewall" ).rules.inline ).toHaveLength( 1 );
				} );
			} );

			describe( "module settings rule loading", function(){
				beforeEach( function( currentSpec ){
					settings.firewall.rules.inline = [];
					mockValidator                  = mockWireBox.getInstance( settings.firewall.validator );
					security
						.$property( propertyName = "securityModules", mock = {} )
						.$property(
							propertyName = "log",
							mock         = {
								info : function(){
								}
							}
						)
						.$( "getInstance" )
						.$args( settings.firewall.validator )
						.$results( mockValidator );
				} );

				it( "can load JSON Rules based on module settings", function(){
					expect( security.getProperty( "firewall" ).rules.inline ).toHaveLength( 0 );
					var source = expandPath( "/tests/resources/security.json.cfm" );
					mockController.$( "locateFilePath", source );

					// initiate cbSecurity's module registration rule parsing
					security.registerModule(
						"myTestModule",
						{ firewall : { rules : { provider : { source : source } } } }
					);

					expect( security.getProperty( "firewall" ).rules.inline ).toHaveLength( 2 );
				} );

				it( "can load XML Rules based on module settings", function(){
					var source = expandPath( "/tests/resources/security.xml.cfm" );
					mockController.$( "locateFilePath", source );

					// initiate cbSecurity's module registration rule parsing
					security.registerModule(
						"myTestModule",
						{ firewall : { rules : { provider : { source : source } } } }
					);

					expect( security.getProperty( "firewall" ).rules.inline ).toHaveLength( 3 );
				} );

				it( "can load model Rules based on module settings", function(){
					var moduleSettings = {
						firewall : {
							rules : {
								provider : {
									source     : "model",
									properties : {
										model  : "tests.resources.security",
										method : "getSecurityRules"
									}
								}
							}
						}
					};

					// initiate cbSecurity's module registration rule parsing
					security.registerModule( "myTestModule", moduleSettings );

					expect( security.getProperty( "firewall" ).rules.inline ).toHaveLength( 1 );
				} );
			} );

			describe( "URL validation for open redirect prevention", () => {

				beforeEach( ( currentSpec ) => {
					mockValidator = mockWireBox.getInstance( settings.firewall.validator );
					security
						.$( "getInstance" )
						.$args( settings.firewall.validator )
						.$results( mockValidator );
					security.configure();

					mockSecurityService.$( "getRealHost", "mysite.com" );

					mockEvent = createMock( "coldbox.system.web.context.RequestContext" )
						.$( "getCurrentRoutedURL", "/account" )
						.$( "buildLink" )
						.$args( to = "/account", queryString = "", translate = false )
						.$results( "/account" )
						.$( "setValue" );

					mockFlash = createStub().$( "put" );
					security.$property( "flash", "variables", mockFlash );

                    makePublic( security, "isSafeRedirectUrl" );
                    makePublic( security, "saveSecuredUrl" );
				} );

				it( "allows relative URLs without a host", () => {
                    var result = security.isSafeRedirectUrl( targetUrl = "/account", event = mockEvent );
					expect( result ).toBeTrue();
				} );

				it( "allows URLs with the same host", () => {
					var result = security.isSafeRedirectUrl( targetUrl = "https://mysite.com/account", event = mockEvent );
					expect( result ).toBeTrue();
				} );

				it( "blocks URLs with different hosts", () => {
					var result = security.isSafeRedirectUrl( targetUrl = "https://malicioussite.com/phishing", event = mockEvent );
					expect( result ).toBeFalse();
				} );

				it( "blocks URLs with subdomain differences", () => {
					var result = security.isSafeRedirectUrl( targetUrl = "https://evil.mysite.com/account", event = mockEvent );
					expect( result ).toBeFalse();
				} );

				it( "is case-insensitive when comparing hosts", () => {
					var result = security.isSafeRedirectUrl( targetUrl = "https://MySite.COM/account", event = mockEvent );
					expect( result ).toBeTrue();
				} );

				it( "handles invalid URLs gracefully", () => {
					var result = security.isSafeRedirectUrl( targetUrl = "not a valid url://", event = mockEvent );
					expect( result ).toBeFalse();
				} );

				it( "saves secured URL when it is safe", () => {
                    mockEvent.$( "getCurrentRoutedURL", "/account" );
					mockEvent
                        .$( "buildLink" )
						.$args( to = "/account", queryString = cgi.QUERY_STRING, translate = false )
						.$results( "/account" );

					security.saveSecuredUrl( mockEvent );

					// Verify flash was called with the safe URL
					expect( mockFlash.$callLog().put ).toHaveLength( 1 );
					expect( mockFlash.$callLog().put[ 1 ][ 1 ] ).toBe( "_securedUrl" );
					expect( mockFlash.$callLog().put[ 1 ][ 2 ] ).toBe( "/account" );
				} );
			} );
		} );
	}

	private function createRuleLoader(){
		return createMock( "cbsecurity.models.util.RulesLoader" )
			.init()
			.setController( variables.mockController )
			.setWireBox( variables.mockWireBox );
	}

}
