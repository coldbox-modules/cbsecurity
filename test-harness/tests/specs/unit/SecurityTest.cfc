component
	extends="coldbox.system.testing.BaseInterceptorTest"
	interceptor="cbsecurity.interceptors.Security"
{

	function beforeAll(){
		super.beforeAll();
	}

	/*********************************** BDD SUITES ***********************************/

	function run( testResults, testBox ){
		// all your suites go here.
		describe( "Security Interceptor Unit Tests", function(){

			beforeEach(function( currentSpec ){
				// setup properties
				setup();
				variables.wirebox = new coldbox.system.ioc.Injector();
				mockController
					.$( "getAppHash", hash( "appHash" ) )
					.$( "getAppRootPath", expandPath( "/root" ) );
				security = interceptor;
				settings = {
					"rules"				: [],
					// Where are the rules, valid options: json,xml,db,model
					"rulesSource" 		: "",
					// The location of the rules file, applies to json|xml ruleSource
					"rulesFile"			: "",
					// The rule validator model, this must have a method like this `userValidator( rule, controller ):boolean`
					"validator"			: "CFValidator@cbsecurity",
					// If source is model, the wirebox Id to use for retrieving the rules
					"rulesModel"		: "",
					// If source is model, then the name of the method to get the rules, we default to `getSecurityRules`
					"rulesModelMethod"	: "getSecurityRules",
					// If source is db then the datasource name to use
					"rulesDSN"			: "",
					// If source is db then the table to get the rules from
					"rulesTable"		: "",
					// If source is db then the ordering of the select
					"rulesOrderBy"		: "",
					// If source is db then you can have your custom select SQL
					"rulesSql" 			: "",
					// Use regular expression matching on the rules
					"useRegex" 			: true,
					// Force SSL for all relocations
					"useSSL"			: false,
					"preEventSecurity"	: false
				};
			});


			it( "can configure with invalid settings", function(){
				security.setProperties( settings );

				settings.rulessource = "json";
				expect( function(){
					security.configure();
				}).toThrow( "Security.RulesFileNotDefined" );

				settings.rulessource = "hello";
				security.setProperties( settings );
				expect( function(){
					security.configure();
				}).toThrow( "Security.InvalidRuleSource" );

				settings.rulessource = "db";
				expect( function(){
					security.configure();
				}).toThrow( "Security.RuleDSNNotDefined" );

				settings.rulesDSN = "test";
				expect( function(){
					security.configure();
				}).toThrow( "Security.RulesTableNotDefined" );

				settings.rulesSource = "model";
				expect( function(){
					security.configure();
				}).toThrow( "Security.RulesModelNotDefined" );
			});

			it( "can configure with valid settings", function(){
				settings.rulesSource = "json";
				settings.rulesFile = expandPath( "/tests/resources/security.json.cfm" );
				security.setProperties( settings );
				security.configure();

				expect( security.getProperty( "rules", [] ) ).toBeEmpty();
			});

			it( "can unregister the pre event security if configured on load", function(){
				// pre event security check
				settings.validator = "tests.resources.security";
				mockRuleLoader = createRuleLoader().$( "loadRules", [] );

				security
					.$( "unregister", true )
					.$( "getInstance" ).$args( "RulesLoader@cbSecurity" ).$results( mockRuleLoader )
					.$( "getInstance" ).$args( settings.validator ).$results(
						wirebox.getInstance( settings.validator )
					)
					.setProperties( settings )
					.setProperty( "preEventSecurity", false );

				security.afterAspectsLoad( getMockRequestContext(), {} );
				expect( security.$once( "unregister" ) ).toBeTrue();
				expect( security.getInitialized() ).toBeTrue();
			});

			describe( "It can load many types of rules", function(){

				beforeEach(function( currentSpec ){
					// pre event security check
					ruleLoader = createRuleLoader();
					settings.validator = "tests.resources.security";
					security
						.$( "getInstance" ).$args( "RulesLoader@cbSecurity" ).$results( ruleLoader )
						.$( "getInstance" ).$args( settings.validator ).$results(
							wirebox.getInstance( settings.validator )
						);
				});

				it( "can load JSON Rules", function(){
					settings.rulesSource 		= "json";
					settings.rulesFile 			= expandPath( "/tests/resources/security.json.cfm" );
					settings.preEventSecurity 	= true;
					mockController.$( "locateFilePath", settings.rulesFile );
					security.setProperties( settings );

					security.afterAspectsLoad( getMockRequestContext(), {} );

					expect( security.getProperty( "rules", [] ) ).toHaveLength( 2 );
					expect( security.getInitialized() ).toBeTrue();
				});

				it( "can load XML Rules", function(){
					settings.rulesSource 		= "xml";
					settings.rulesFile 			= expandPath( "/tests/resources/security.xml.cfm" );
					settings.preEventSecurity 	= true;
					mockController.$( "locateFilePath", settings.rulesFile );
					security.setProperties( settings );

					security.afterAspectsLoad( getMockRequestContext(), {} );

					expect( security.getProperty( "rules", [] ) ).toHaveLength( 3 );
					expect( security.getInitialized() ).toBeTrue();
				});

				it( "can load model Rules", function(){
					settings.rulesSource 		= "model";
					settings.rulesModel			= "tests.resources.security";
					settings.preEventSecurity 	= true;
					security.setProperties( settings );

					security.afterAspectsLoad( getMockRequestContext(), {} );

					expect( security.getProperty( "rules", [] ) ).toHaveLength( 1 );
					expect( security.getInitialized() ).toBeTrue();
				});

			});

			it( "can load a valid validator", function(){
				settings.rulesSource = "json";
				settings.rulesFile = expandPath( "/tests/resources/security.json.cfm" );
				settings.validator = "tests.resources.security";
				settings.preEventSecurity = true;
				mockRuleLoader = createRuleLoader().$( "loadRules", [] );

				security
					.setProperties( settings )
					.$( "getInstance" ).$args( "RulesLoader@cbSecurity" ).$results( mockRuleLoader )
					.$( "getInstance" ).$args( settings.validator ).$results(
						wirebox.getInstance( settings.validator )
					);

				security.afterAspectsLoad( getMockRequestContext(), {} );
				expect( security.getValidator() ).toBeComponent();
			});

			it( "can detect an invalid validator", function(){
				settings.rulesSource = "json";
				settings.rulesFile = expandPath( "/tests/resources/security.json.cfm" );
				settings.validator = "invalid.path";
				settings.preEventSecurity = true;
				mockRuleLoader = createRuleLoader().$( "loadRules", [] );

				security
					.setProperties( settings )
					.$( "getInstance" ).$args( "RulesLoader@cbSecurity" ).$results( mockRuleLoader )
					.$( "getInstance" ).$args( settings.validator ).$results( createStub() );

				expect( function(){
					security.afterAspectsLoad( getMockRequestContext(), {} );
				}).toThrow( "Security.ValidatorMethodException" );

			});

		});
	}

	private function createRuleLoader(){
		return createMock( "cbsecurity.models.RulesLoader" )
			.init()
			.setController( variables.mockController )
			.setWireBox( variables.wirebox );
	}

}