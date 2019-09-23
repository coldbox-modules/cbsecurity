component{
	// Configure ColdBox Application
	function configure(){
		// coldbox directives
		coldbox = {
			// Application Setup
			appName : "Module Tester",
			// Development Settings
			reinitPassword : "",
			handlersIndexAutoReload : true,
			modulesExternalLocation : [],
			// Implicit Events
			defaultEvent : "",
			requestStartHandler : "",
			requestEndHandler : "",
			applicationStartHandler : "",
			applicationEndHandler : "",
			sessionStartHandler : "",
			sessionEndHandler : "",
			missingTemplateHandler : "",
			// Error/Exception Handling
			exceptionHandler : "",
			onInvalidEvent : "",
			customErrorTemplate : "/coldbox/system/includes/BugReport.cfm",
			// Application Aspects
			handlerCaching : false,
			eventCaching : false
		};

		// environment settings, create a detectEnvironment() method to detect it yourself.
		// create a function with the name of the environment so it can be executed if that environment is detected
		// the value of the environment is a list of regex patterns to match the cgi.http_host.
		environments = { development : "localhost,127\.0\.0\.1" };

		// Module Directives
		modules = {
			// An array of modules names to load, empty means all of them
			include : [],
			// An array of modules names to NOT load, empty means none
			exclude : []
		};

		// Register interceptors as an array, we need order
		interceptors = [
			// SES
			{ class : "coldbox.system.interceptors.SES" }
		];

		// LogBox DSL
		logBox = {
			// Define Appenders
			appenders : {
				files : {
					class : "coldbox.system.logging.appenders.RollingFileAppender",
					properties : { filename : "tester", filePath : "/#appMapping#/logs" }
				},
				console : {
					class : "coldbox.system.logging.appenders.ConsoleAppender"
				}
			},
			// Root Logger
			root : { levelmax : "DEBUG", appenders : "*" },
			// Implicit Level Categories
			info : [ "coldbox.system" ]
		};

		// Module Settings
		moduleSettings = {
			// CB Auth
			cbAuth : {
				userServiceClass : "UserService"
			},
			// CB Security
			cbSecurity : {
				// Global Relocation when an invalid access is detected, instead of each rule declaring one.
				"invalidAuthenticationEvent" 	: "main.index",
				// Global override event when an invalid access is detected, instead of each rule declaring one.
				"invalidAuthorizationEvent"		: "main.index",
				// Default invalid action: override or redirect when an invalid access is detected, default is to redirect
				"defaultAuthorizationAction"	: "redirect",
				// The WireBox ID of the authentication service to use in cbSecurity which must adhere to the cbsecurity.interfaces.IAuthService interface.
				"authenticationService"  		: "authenticationService@cbauth",
				// WireBox ID of the user service to use
				"userService"             		: "UserService",
				// Enable Visualizer
				"enableSecurityVisualizer"		: true,
				// The global security rules
				"rules" 						: [
					// should use direct action and do a global redirect
					{
						"whitelist": "",
						"securelist": "admin",
						"match": "event",
						"roles": "admin",
						"permissions": "",
						"action" : "redirect"
					},
					// no action, use global default action
					{
						"whitelist": "",
						"securelist": "noAction",
						"match": "url",
						"roles": "admin",
						"permissions": ""
					},
					// Using overrideEvent only, so use an explicit override
					{
						"securelist": "ruleActionOverride",
						"match": "url",
						"overrideEvent": "main.login"
					},
					// direct action, use global override
					{
						"whitelist": "",
						"securelist": "override",
						"match": "url",
						"roles": "",
						"permissions": "",
						"action" : "override"
					},
					// Using redirect only, so use an explicit redirect
					{
						"securelist": "ruleActionRedirect",
						"match": "url",
						"redirect": "main.login"
					}
				],
				// JWT Settings
				"jwt"                     		: {
					// The jwt secret encoding key, defaults to getSystemEnv( "JWT_SECRET", "" )
					"secretKey"               : "C3D4AF35-8FCD-49AB-943A39AEFFB584EE",
					// by default it uses the authorization bearer header, but you can also pass a custom one as well.
					"customAuthHeader"        : "x-auth-token",
					// The expiration in minutes for the jwt tokens
					"expiration"              : 60,
					// If true, enables refresh tokens, longer lived tokens (not implemented yet)
					"enableRefreshTokens"     : false,
					// The default expiration for refresh tokens, defaults to 30 days
					"refreshExpiration"       : 43200,
					// encryption algorithm to use, valid algorithms are: HmacSHA256, HmacSHA384, and HmacSHA512
					"algorithm"               : "HmacSHA512",
					// Which claims neds to be present on the jwt token or `TokenInvalidException` upon verification and decoding
					"requiredClaims"          : [ "role" ],
					// The token storage settings
					"tokenStorage"            : {
						// enable or not, default is true
						"enabled"       : true,
						// A cache key prefix to use when storing the tokens
						"keyPrefix"     : "cbjwt_",
						// The driver to use: db, cachebox or a WireBox ID
						"driver"        : "cachebox",
						// Driver specific properties
						"properties"    : {
							"cacheName" : "default"
						}
					}
				}
			}
		};
	}

	/**
	 * Load the Module you are testing
	 */
	function afterConfigurationLoad( event, interceptData, rc, prc ){
		controller
			.getModuleService()
			.registerAndActivateModule( moduleName = request.MODULE_NAME, invocationPath = "moduleroot" );
	}
}
