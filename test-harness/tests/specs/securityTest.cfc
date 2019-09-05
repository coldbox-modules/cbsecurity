component extends="coldbox.system.testing.BaseInterceptorTest" interceptor="cbsecurity.interceptors.Security" {

	function setup(){
		// setup properties
		super.setup();
		mockController.$( "getAppHash", hash( "appHash" ) ).$( "getAppRootPath", expandPath( "/root" ) );

		security = interceptor;
	}

	function testConfigure(){
		props = { useRegex : true, rulesSource : "xml" };
		security.setProperties( props );
		security.$( "rulesSourceChecks" );
		security.configure();

		assertEquals( false, security.getProperty( "rulesLoaded" ) );
		assertEquals( [], security.getProperty( "rules" ) );
	}

	function testAfterAspectsLoad(){
		// pre event security check
		security.$( "unregister", true ).setProperty( "preEventSecurity", false );
		security.setProperty( "rulesSource", "" );
		security.afterAspectsLoad( getMockRequestContext(), {} );
		assertTrue( security.$once( "unregister" ) );

		// load xml
		security.$( "loadXMLRules" ).setProperty( "rulesSource", "xml" );
		security.afterAspectsLoad( getMockRequestContext(), {} );
		assertTrue( security.$once( "loadXMLRules" ) );

		// load db
		security.$( "loadDBRules" ).setProperty( "rulesSource", "db" );
		security.afterAspectsLoad( getMockRequestContext(), {} );
		assertTrue( security.$once( "loadDBRules" ) );

		// load ioc
		security.$( "loadIOCRules" ).setProperty( "rulesSource", "ioc" );
		security.afterAspectsLoad( getMockRequestContext(), {} );
		assertTrue( security.$once( "loadIOCRules" ) );

		// load model
		security.$( "loadModelRules" ).setProperty( "rulesSource", "model" );
		security.afterAspectsLoad( getMockRequestContext(), {} );
		assertTrue( security.$once( "loadModelRules" ) );
	}

	function testRegisterValidator(){
		var validator = createObject( "component", "tests.resources.security" );

		/* Register */
		security.registerValidator( validator );
		assertEquals( validator, security.getValidator() );
	}

	function testLoadRules(){
		interceptor
			.$( "loadXMLRules" )
			.$( "loadJSONRules" )
			.$( "loadDBRules" )
			.$( "loadIOCRules" )
			.$( "loadModelRules" );

		interceptor.$( "getProperty", "xml" ).loadRules();
		assertTrue( interceptor.$once( "loadXMLRules" ) );

		interceptor.$( "getProperty", "json" ).loadRules();
		assertTrue( interceptor.$once( "loadJSONRules" ) );

		interceptor.$( "getProperty", "db" ).loadRules();
		assertTrue( interceptor.$once( "loadDBRules" ) );

		interceptor.$( "getProperty", "ioc" ).loadRules();
		assertTrue( interceptor.$once( "loadIOCRules" ) );

		interceptor.$( "getProperty", "model" ).loadRules();
		assertTrue( interceptor.$once( "loadModelRules" ) );
	}

	function testLoadJSONRules(){
		interceptor.getProperties().rulesFile = expandPath( "/tests/resources/security.json.cfm" );
		interceptor.getProperties().rules = [];
		mockController.$( "locateFilePath", interceptor.getProperties().rulesFile );
		makePublic( interceptor, "loadJSONRules" );
		interceptor.loadJSONRules();

		assert( arrayLen( interceptor.getProperty( "rules" ) ) eq 2 );
	}

}
