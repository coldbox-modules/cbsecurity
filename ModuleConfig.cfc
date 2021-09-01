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
	this.dependencies      = [ "cbauth", "jwtcfml" ];

	/**
	 * Module Config
	 */
	function configure(){
		settings = {
			// The global invalid authentication event or URI or URL to go if an invalid authentication occurs
			"invalidAuthenticationEvent"  : "",
			// Default Auhtentication Action: override or redirect when a user has not logged in
			"defaultAuthenticationAction" : "redirect",
			// The global invalid authorization event or URI or URL to go if an invalid authorization occurs
			"invalidAuthorizationEvent"   : "",
			// Default Authorization Action: override or redirect when a user does not have enough permissions to access something
			"defaultAuthorizationAction"  : "redirect",
			// You can define your security rules here or externally via a source
			"rules"                       : [],
			// The validator is an object that will validate rules and annotations and provide feedback on either authentication or authorization issues.
			"validator"                   : "CBAuthValidator@cbsecurity",
			// The WireBox ID of the authentication service to use in cbSecurity which must adhere to the cbsecurity.interfaces.IAuthService interface.
			"authenticationService"       : "authenticationService@cbauth",
			// WireBox ID of the user service to use
			"userService"                 : "",
			// The name of the variable to use to store an authenticated user in prc scope if using a validator that supports it.
			"prcUserVariable"             : "oCurrentUser",
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
			// Use regular expression matching on the rule match types
			"useRegex"                    : true,
			// Force SSL for all relocations
			"useSSL"                      : false,
			// Auto load the global security firewall
			"autoLoadFirewall"            : true,
			// Activate handler/action based annotation security
			"handlerAnnotationSecurity"   : true,
			// Activate security rule visualizer, defaults to false by default
			"enableSecurityVisualizer"    : false,
			// JWT Settings
			"jwt"                         : {
				// The issuer authority for the tokens, placed in the `iss` claim
				"issuer"                     : "",
				// The jwt secret encoding key to use
				"secretKey"                  : getSystemSetting( "JWT_SECRET", "" ),
				// by default it uses the authorization bearer header, but you can also pass a custom one as well or as an rc variable.
				"customAuthHeader"           : "x-auth-token",
				// The expiration in minutes for the jwt tokens
				"expiration"                 : 60,
				// If true, enables refresh tokens, token creation methods will return a struct instead
				// of just the access token. e.g. { access_token: "", refresh_token : "" }
				"enableRefreshTokens"        : false,
				// The default expiration for refresh tokens, defaults to 30 days
				"refreshExpiration"          : 10080,
				// The Custom header to inspect for refresh tokens
				"customRefreshHeader"        : "x-refresh-token",
				// If enabled, the JWT validator will inspect the request for refresh tokens and expired access tokens
				// It will then automatically refresh them for you and return them back as
				// response headers in the same request according to the customRefreshHeader and customAuthHeader
				"enableAutoRefreshValidator" : false,
				// Enable the POST > /cbsecurity/refreshtoken API endpoint
				"enableRefreshEndpoint"      : true,
				// encryption algorithm to use, valid algorithms are: HS256, HS384, and HS512
				"algorithm"                  : "HS512",
				// Which claims neds to be present on the jwt token or `TokenInvalidException` upon verification and decoding
				"requiredClaims"             : [],
				// The token storage settings
				"tokenStorage"               : {
					// enable or not, default is true
					"enabled"    : true,
					// A cache key prefix to use when storing the tokens
					"keyPrefix"  : "cbjwt_",
					// The driver to use: db, cachebox or a WireBox ID
					"driver"     : "cachebox",
					// Driver specific properties
					"properties" : { "cacheName" : "default" }
				}
			}
		};

		// CBSecurity Routes
		router.post( "/refreshtoken" ).to( "Home.refreshToken" );
		router.route( "/" ).to( "Home.index" );

		// Security Interceptions
		interceptorSettings = {
			customInterceptionPoints : [
				// Validator Events
				"cbSecurity_onInvalidAuthentication",
				"cbSecurity_onInvalidAuthorization",
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
		// Check the global settings for rules or a rules source
		if ( settings.autoLoadFirewall ) {
			controller
				.getInterceptorService()
				.registerInterceptor(
					interceptorClass      = "cbsecurity.interceptors.Security",
					interceptorProperties = settings,
					interceptorName       = "cbsecurity@global"
				);
		}
	}

	/**
	 * Fired when the module is unregistered and unloaded
	 */
	function onUnload(){
	}

}
