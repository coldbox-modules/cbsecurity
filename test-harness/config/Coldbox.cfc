component{
	// Configure ColdBox Application
	function configure(){
		// coldbox directives
		coldbox = {
			// Application Setup
			appName                 : "Module Tester",
			// Development Settings
			reinitPassword          : "",
			handlersIndexAutoReload : true,
			modulesExternalLocation : [],
			// Implicit Events
			defaultEvent            : "",
			requestStartHandler     : "",
			requestEndHandler       : "",
			applicationStartHandler : "",
			applicationEndHandler   : "",
			sessionStartHandler     : "",
			sessionEndHandler       : "",
			missingTemplateHandler  : "",
			// Error/Exception Handling
			exceptionHandler        : "",
			onInvalidEvent          : "",
			customErrorTemplate     : "/coldbox/system/exceptions/Whoops.cfm",
			// Application Aspects
			handlerCaching          : false,
			eventCaching            : false,
			autoMapModels           : true
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
		interceptors = [];

		// LogBox DSL
		logBox = {
			// Define Appenders
			appenders : {
				files : {
					class      : "coldbox.system.logging.appenders.RollingFileAppender",
					properties : { filename : "tester", filePath : "/#appMapping#/logs" }
				},
				console : { class : "coldbox.system.logging.appenders.ConsoleAppender" }
			},
			// Root Logger
			root  : { levelmax : "DEBUG", appenders : "*" },
			// Implicit Level Categories
			info  : [ "coldbox.system" ],
			debug : [ "cbsecurity" ]
		};

		// Module Settings
		moduleSettings = {
			// CBDebugger
			cbdebugger : {
				modules  : { enabled : true, expanded : false }
			},
			// CB Auth
			cbAuth     : { userServiceClass : "UserService" },
			// CB Security
			cbSecurity : {

				basicAuth : {
					users : {
						"lmajano" : { password : 'test', permissions : "", roles : "admin" },
						"test" : { password: "test", roles : "guest" }
					}
				},

				authentication : {
					// The WireBox ID of the authentication service to use in cbSecurity which must adhere to the cbsecurity.interfaces.IAuthService interface.
					"provider"      : "authenticationService@cbauth"
				},

				firewall : {
					// Global Relocation when an invalid access is detected, instead of each rule declaring one.
					"invalidAuthenticationEvent" : "main.index",
					// Default invalid action: override or redirect when an invalid access is detected, default is to redirect
					"defaultAuthenticationAction" : "redirect",
					// Global override event when an invalid access is detected, instead of each rule declaring one.
					"invalidAuthorizationEvent"  : "main.index",
					// Default invalid action: override or redirect when an invalid access is detected, default is to redirect
					"defaultAuthorizationAction" : "redirect",
					// Firewall Validator
					//"validator"                   : "BasicAuthValidator@cbsecurity",
					"logs" : {
						enabled : true
					},
					// The global security rules
					"rules"                      : [
						// should use direct action and do a global redirect
						{
							"whitelist"   : "",
							"securelist"  : "admin",
							"match"       : "event",
							"roles"       : "admin",
							"permissions" : "",
							"action"      : "redirect",
							"httpMethods" : "*"
						},
						// Match only put/post
						{
							"whitelist"   : "",
							"securelist"  : "putpost",
							"match"       : "event",
							"roles"       : "",
							"permissions" : "",
							"action"      : "block",
							"httpMethods" : "put,post"
						},
						{
							"whitelist"   : "",
							"securelist"  : "cfide",
							"match"       : "url",
							"roles"       : "",
							"permissions" : "",
							"action"      : "redirect",
							"allowedIPs"  : "10.0.0.1"
						},
						// no action, use global default action
						{
							"whitelist"   : "",
							"securelist"  : "noAction",
							"match"       : "url",
							"roles"       : "admin",
							"permissions" : "",
							"httpMethods" : "*"
						},
						// Using overrideEvent only, so use an explicit override
						{
							"securelist" : "ruleActionOverride",
							"match" : "url",
							"overrideEvent" : "main.login",
							"httpMethods" : "*"
						},
						// direct action, use global override
						{
							"whitelist"   : "",
							"securelist"  : "override",
							"match"       : "url",
							"roles"       : "",
							"permissions" : "",
							"action"      : "override",
							"httpMethods" : "*"
						},
						// Using redirect only, so use an explicit redirect
						{
							"securelist" : "ruleActionRedirect",
							"match" : "url",
							"redirect" : "main.login",
							"httpMethods" : "*"
						}
					]
				},

				// Security Headers
				"securityHeaders" : {
					"frameOptions" : {
						"value" : "sameOrigin"
					},
					"hostHeaderValidation" : {
						"enabled"       : true,
						// Allowed hosts list
						"allowedHosts"  : "*"
					},
					// Validates the ip address of the incoming request
					"ipValidation" : {
						"enabled"    : true,
						// Allowed IP list
						"allowedIPs" : "*"
					}
				},

				visualizer : {
					enabled : true,
					secured : false,
					// The needed permissions to view the visualizer
					permissions : ""
				},

				// JWT Settings
				"jwt" : {
					"secretKey"           : "C3D4AF35-8FCD-49AB-943A39AEFFB584EE",
					"customAuthHeader"    : "x-auth-token",
					//"expiration"          : 60,
					//"enableRefreshTokens" : false,
					//"refreshExpiration"   : 43200,
					"algorithm"           : "HS512",
					"requiredClaims"      : [ "role" ],
					"tokenStorage"        : {
						"enabled"    : true,
						"keyPrefix"  : "cbjwt_",
						//"driver"     : "cachebox",
						//"properties" : { "cacheName" : "default" }

						"driver"     : "db",
						"properties" : { "table" : "jwtTokens" }
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
