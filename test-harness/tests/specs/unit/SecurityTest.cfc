component extends="coldbox.system.testing.BaseInterceptorTest" interceptor="cbsecurity.interceptors.Security" {

	function beforeAll(){
		super.beforeAll();
	}

	/*********************************** BDD SUITES ***********************************/

	function run( testResults, testBox ){
		// all your suites go here.
		describe( "Security Interceptor Unit Tests", function(){
			beforeEach( function(currentSpec){
				// setup properties
				setup();
				variables.wirebox = new coldbox.system.ioc.Injector();
                mockController
                    .$( "getAppHash", hash( "appHash" ) )
                    .$( "getAppRootPath", expandPath( "/root" ) )
                    .$( "getColdboxSettings", {
                        "version": "6.0.0"
                    }, false  );
                security = interceptor;
                security.setInvalidEventHandler( '' );
				settings = {
					// The global invalid authentication event or URI or URL to go if an invalid authentication occurs
					"invalidAuthenticationEvent"  : "",
					// Default Auhtentication Action: override or redirect when a user has not logged in
					"defaultAuthenticationAction" : "redirect",
					// The global invalid authorization event or URI or URL to go if an invalid authorization occurs
					"invalidAuthorizationEvent"   : "",
					// Default invalid action: override or redirect when an invalid access is detected, default is to redirect
					"defaultAuthorizationAction"  : "redirect",
					"rules"                       : [],
					// Where are the rules, valid options: json,xml,db,model
					"rulesSource"                 : "",
					// The location of the rules file, applies to json|xml ruleSource
					"rulesFile"                   : "",
					// The rule validator model, this must have a method like this `userValidator( rule, controller ):boolean`
					"validator"                   : "tests.resources.security",
					// If source is model, the wirebox Id to use for retrieving the rules
					"rulesModel"                  : "",
					// If source is model, then the name of the method to get the rules, we default to `getSecurityRules`
					"rulesModelMethod"            : "getSecurityRules",
					// If source is db then the datasource name to use
					"rulesDSN"                    : "",
					// If source is db then the table to get the rules from
					"rulesTable"                  : "",
					// If source is db then the ordering of the select
					"rulesOrderBy"                : "",
					// If source is db then you can have your custom select SQL
					"rulesSql"                    : "",
					// Use regular expression matching on the rules
					"useRegex"                    : true,
					// Force SSL for all relocations
					"useSSL"                      : false,
					// Auto load the global security firewall
					"autoLoadFirewall"            : true,
					// Activate handler/action based annotation security
					"handlerAnnotationSecurity"   : true
				};
				// Set Rule Loader
				security.setRulesLoader( createRuleLoader() );
			} );

			it( "can configure with invalid settings", function(){
				security.setProperties( settings );

				settings.rulessource = "json";
				expect( function(){
					security.configure();
				} ).toThrow( "Security.RulesFileNotDefined" );

				settings.rulessource = "hello";
				security.setProperties( settings );
				expect( function(){
					security.configure();
				} ).toThrow( "Security.InvalidRuleSource" );

				settings.rulessource = "db";
				expect( function(){
					security.configure();
				} ).toThrow( "Security.RuleDSNNotDefined" );

				settings.rulesDSN = "test";
				expect( function(){
					security.configure();
				} ).toThrow( "Security.RulesTableNotDefined" );

				settings.rulesSource = "model";
				expect( function(){
					security.configure();
				} ).toThrow( "Security.RulesModelNotDefined" );
			} );

			it( "can configure with default settings", function(){
				security.setProperties( settings );
				security
					.$( "getInstance" )
					.$args( settings.validator )
					.$results( wirebox.getInstance( settings.validator ) );
				security.configure();
				expect( security.getProperty( "rules", [] ) ).toBeEmpty();
			} );

			it( "can load a valid validator", function(){
				settings.rulesSource = "json";
				settings.rulesFile   = expandPath( "/tests/resources/security.json.cfm" );
				settings.validator   = "tests.resources.security";
				security.getRulesLoader().$( "loadRules", [] );

				security
					.setProperties( settings )
					.$( "getInstance" )
					.$args( settings.validator )
					.$results( wirebox.getInstance( settings.validator ) );

				security.configure();
				expect(
					security.getValidator(
						createMock( "coldbox.system.web.context.RequestContext" ).$( "getCurrentModule", "" )
					)
				).toBeComponent();
			} );

			it( "can detect an invalid validator", function(){
				settings.rulesSource = "json";
				settings.rulesFile   = expandPath( "/tests/resources/security.json.cfm" );
				settings.validator   = "invalid.path";
				security.getRulesLoader().$( "loadRules", [] );

				security
					.setProperties( settings )
					.$( "getInstance" )
					.$args( settings.validator )
					.$results( createStub() );

				expect( function(){
					security.configure();
				} ).toThrow( "Security.ValidatorMethodException" );
            } );

            it( "does not enable invalid event handler processing on Coldbox versions 6+", function() {
                security.setProperties( settings );
				security
					.$( "getInstance" )
					.$args( settings.validator )
					.$results( wirebox.getInstance( settings.validator ) );
				security.configure();
				expect( security.$getProperty( "enableInvalidHandlerCheck" ) ).toBeFalse();
            } );
            
            it( "enables invalid event handler processing on Coldbox versions prior to 6", function() {
                
                mockController.$( "getColdboxSettings", {
                    "version": "5.0.0"
                }, false  );
                
                security.setProperties( settings );
				security
					.$( "getInstance" )
					.$args( settings.validator )
					.$results( wirebox.getInstance( settings.validator ) );
				security.configure();
				expect( security.$getProperty( "enableInvalidHandlerCheck" ) ).toBeTrue();
            } );   

			describe( "It can load many types of rules", function(){
				beforeEach( function(currentSpec){
					settings.validator = "tests.resources.security";
					security
						.$( "getInstance" )
						.$args( settings.validator )
						.$results( wirebox.getInstance( settings.validator ) );
				} );

				it( "can load JSON Rules", function(){
					settings.rulesSource = "json";
					settings.rulesFile   = expandPath( "/tests/resources/security.json.cfm" );
					mockController.$( "locateFilePath", settings.rulesFile );
					security.setProperties( settings );

					security.configure();

					expect( security.getProperty( "rules", [] ) ).toHaveLength( 2 );
				} );

				it( "can load XML Rules", function(){
					settings.rulesSource = "xml";
					settings.rulesFile   = expandPath( "/tests/resources/security.xml.cfm" );
					mockController.$( "locateFilePath", settings.rulesFile );
					security.setProperties( settings );

					security.configure();

					expect( security.getProperty( "rules", [] ) ).toHaveLength( 3 );
				} );

				it( "can load model Rules", function(){
					settings.rulesSource = "model";
					settings.rulesModel  = "tests.resources.security";
					security.setProperties( settings );

					security.configure();

					expect( security.getProperty( "rules", [] ) ).toHaveLength( 1 );
				} );
            } );
            
		} );
	}

	private function createRuleLoader(){
		return createMock( "cbsecurity.models.util.RulesLoader" )
			.init()
			.setController( variables.mockController )
			.setWireBox( variables.wirebox );
	}

}
