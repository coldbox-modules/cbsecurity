/**
 * Copyright Since 2005 ColdBox Framework by Luis Majano and Ortus Solutions, Corp
 * ---
 * Module Configuration
 */
component {

	// Module Properties
	this.title             = "cbsecurity";
	this.author            = "Ortus Solutions, Corp";
	this.webURL            = "https://www.ortussolutions.com";
	this.description       = "This module provides robust security for ColdBox Apps";
	// Model Namespace
	this.modelNamespace    = "cbsecurity";
	// CF Mapping
	this.cfmapping         = "cbsecurity";
	// Entry Point
	this.entryPoint        = "cbsecurity";
	// Helpers
	this.applicationHelper = [ "helpers/mixins.cfm" ];
	// Dependencies
	this.dependencies      = [ "cbauth", "jwtcfml", "cbcsrf" ];

	/**
	 * Module Config
	 */
	function configure(){
		settings = {
			/**
			 * --------------------------------------------------------------------------
			 * Authentication Services
			 * --------------------------------------------------------------------------
			 * Here you will configure which service is in charge of providing authentication for your application.
			 * By default we leverage the cbauth module which expects you to connect it to a database via your own User Service.
			 *
			 * Available authentication providers:
			 * - cbauth : Leverages your own UserService that determines authentication and user retrieval
			 * - basicAuth : Leverages basic authentication and basic in-memory user registration in our configuration
			 * - custom : Any other service that adheres to our IAuthService interface
			 */
			authentication : {
				// The WireBox ID of the authentication service to use which must adhere to the cbsecurity.interfaces.IAuthService interface.
				"provider" : "authenticationService@cbauth"
			},
			/**
			 * --------------------------------------------------------------------------
			 * Basic Auth
			 * --------------------------------------------------------------------------
			 * These settings are used so you can configure the hashing patterns of the user storage
			 * included with cbsecurity.  These are only used if you are using the `BasicAuthUserService` as
			 * your service of choice alongside the `BasicAuthValidator`
			 */
			basicAuth : {
				// Hashing algorithm to use
				hashAlgorithm  : "SHA-512",
				// Iterates the number of times the hash is computed to create a more computationally intensive hash.
				hashIterations : 5,
				// User storage: The `key` is the username. The value is the user credentials that can include
				// { roles: "", permissions : "", firstName : "", lastName : "", password : "" }
				users          : {}
			},
			/**
			 * --------------------------------------------------------------------------
			 * CSRF - Cross Site Request Forgery Settings
			 * --------------------------------------------------------------------------
			 * These settings configures the cbcsrf module. Look at the module configuration for more information
			 */
			csrf : {},
			/**
			 * --------------------------------------------------------------------------
			 * Firewall Settings
			 * --------------------------------------------------------------------------
			 * The firewall is used to block/check access on incoming requests via security rules or via annotation on handler actions.
			 * Here you can configure the operation of the firewall and especially what Validator will be in charge of verifying authentication/authorization
			 * during a matched request.
			 */
			firewall : {
				// Auto load the global security firewall automatically, else you can load it a-la-carte via the `Security` interceptor
				"autoLoadFirewall" : true
			},
			/**
			 * --------------------------------------------------------------------------
			 * Security Visualizer
			 * --------------------------------------------------------------------------
			 * This is a debugging panel that when active, a developer can visualize security settings and more.
			 * You can use the `securityRule` to define what rule you want to use to secure the visualizer but make sure the `secured` flag is turned to true.
			 * You don't have to specify the `secureList` key, we will do that for you.
			 */
			visualizer : {
				"enabled"      : false,
				"secured"      : false,
				"securityRule" : {}
			},
			/**
			 * --------------------------------------------------------------------------
			 * Security Headers
			 * --------------------------------------------------------------------------
			 * This section is the way to configure cbsecurity for header detection, inspection and setting for common
			 * security exploits like XSS, ClickJacking, Host Spoofing, IP Spoofing, Non SSL usage, HSTS and much more.
			 */
			securityHeaders : { "enabled" : true },
			/**
			 * --------------------------------------------------------------------------
			 * Json Web Tokens Settings
			 * --------------------------------------------------------------------------
			 * Here you can configure the JWT services for operation and storage.  In order for your firewall
			 * to leverage JWT authentication/authorization you must make sure you use the `JwtAuthValidator` as your
			 * validator of choice; either globally or at the module level.
			 */
			jwt : {
				// The jwt secret encoding key to use
				"secretKey" : getSystemSetting( "JWT_SECRET", "" )
			}
		};

		// Security Interceptions
		interceptorSettings = {
			customInterceptionPoints : [
				// Validator Events
				"cbSecurity_onInvalidAuthentication",
				"cbSecurity_onInvalidAuthorization",
				"cbSecurity_onFirewallBlock",
				// JWT Events
				"cbSecurity_onJWTCreation",
				"cbSecurity_onJWTInvalidation",
				"cbSecurity_onJWTValidAuthentication",
				"cbSecurity_onJWTInvalidUser",
				"cbSecurity_onJWTInvalidClaims",
				"cbSecurity_onJWTExpiration",
				"cbSecurity_onJWTStorageRejection",
				"cbSecurity_onJWTValidParsing",
				"cbSecurity_onJWTInvalidateAllTokens"
			]
		};
	}

	/**
	 * Fired when the module is registered and activated.
	 */
	function onLoad(){
		// Startup the security services, we can't lazy load as we need them immediately so it can protect the application
		wirebox.getInstance( "cbSecurity@cbSecurity" );
		wirebox.getInstance( "BasicAuthUserService@cbSecurity" );

		// Are we auto loading the firewall?
		if ( settings.firewall.autoLoadFirewall ) {
			controller
				.getInterceptorService()
				.registerInterceptor(
					interceptorClass      = "cbsecurity.interceptors.Security",
					interceptorProperties = settings,
					interceptorName       = "cbsecurity@global"
				);
		}

		// Do we load the security headers response interceptor: Default is true even if not defined.
		if ( settings.securityHeaders.enabled ) {
			controller
				.getInterceptorService()
				.registerInterceptor(
					interceptorClass      = "cbsecurity.interceptors.SecurityHeaders",
					interceptorProperties = settings,
					interceptorName       = "securityHeaders@cbsecurity"
				);
		}
	}

	/**
	 * Fired when the module is unregistered and unloaded
	 */
	function onUnload(){
	}

}
