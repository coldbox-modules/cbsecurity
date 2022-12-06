/**
 * Copyright since 2016 by Ortus Solutions, Corp
 * www.ortussolutions.com
 * ---
 * This interceptor provides security to an application. It is very flexible and customizable.
 * It bases off on the ability to secure events by creating rules or annotations on your handlers
 * This interceptor will then try to match a rule to the incoming event and the user's credentials on roles and/or permissions.
 */
component accessors="true" extends="coldbox.system.Interceptor" {

	// DI
	property name="rulesLoader"         inject="rulesLoader@cbSecurity";
	property name="handlerService"      inject="coldbox:handlerService";
	property name="requestService"      inject="coldbox:requestService";
	property name="cbSecurity"          inject="@cbSecurity";
	property name="invalidEventHandler" inject="coldbox:setting:invalidEventHandler";
	property name="DBLogger"            inject="DBLogger@cbsecurity";

	/**
	 * The reference to the security validator for this firewall. One-to-One relationship.
	 */
	property name="validator";

	/**
	 * Configure the security firewall
	 */
	function configure(){
		// Shorthand for rules
		if ( isArray( variables.properties.firewall.rules ) ) {
			variables.properties.firewall.rules = variables.cbSecurity
				.getDefaultRuleSettings()
				.append( { "inline" : variables.properties.firewall.rules }, true );
		}

		// Verify rule providers
		variables.rulesLoader.rulesSourceChecks( variables.properties.firewall.rules.provider );

		// If we added our own inline rules, then normalize them.
		if (
			arrayLen( variables.properties.firewall.rules.inline ) && arrayLen(
				variables.properties.firewall.rules.inline
			)
		) {
			variables.properties.firewall.rules.inline = variables.rulesLoader.normalizeRules(
				rules   : variables.properties.firewall.rules.inline,
				defaults: variables.properties.firewall.rules.defaults
			);
		}

		// Load the rules if a source is defined
		if ( variables.properties.firewall.rules.provider.source.len() ) {
			variables.properties.firewall.rules.inline.append(
				variables.rulesLoader.loadRules(
					variables.properties.firewall.rules.provider,
					variables.properties.firewall.rules.defaults
				),
				true
			);
		}

		// Is visualizer secured or not? Add our own rule
		if ( variables.properties.visualizer.enabled && variables.properties.visualizer.secured ) {
			variables.properties.firewall.rules.inline.prepend(
				variables.rulesLoader
					.getRuleTemplate()
					.append( variables.properties.visualizer.securityRule )
					.append( {
						secureList : "^cbsecurity:Visualizer.*",
						action     : "block"
					} )
			);
		}

		// Coldbox version 5 (and lower) needs a little extra invalid event handler checking.
		variables.enableInvalidHandlerCheck = (
			listGetAt(
				controller.getColdboxSettings().version,
				1,
				"."
			) <= 5
		);

		log.info( "√ CBSecurity Firewall started and configured." );
	}

	/**
	 * Listen when modules are activated to load their cbSecurity capabilities
	 */
	function afterAspectsLoad( event, interceptData, rc, prc, buffer ){
		// Register the validator
		registerValidator( getInstance( variables.properties.firewall.validator ) );

		// Register cbSecurity modules so we can incorporate them.
		controller
			.getSetting( "modules" )
			// Discover cbSecurity modules
			.filter( function( module, config ){
				return (
					arguments.config.settings.keyExists( "cbSecurity" )
					&&
					!structKeyExists( variables.properties.securityModules, arguments.module )
				);
			} )
			// Register module settings
			.each( function( module, config ){
				// Register Module
				registerModule( arguments.module, arguments.config.settings.cbSecurity );
			} );

		// Once ColdBox has loaded, load up the invalid event bean
		variables.onInvalidEventHandlerBean = javacast( "null", "" );
		if ( len( variables.invalidEventHandler ) ) {
			variables.onInvalidEventHandlerBean = variables.handlerService.getHandlerBean(
				variables.invalidEventHandler
			);
		}
	}

	/**
	 * Register a module with cbSecurity by passing it's name and the cbSecurity settings struct
	 *
	 * @module   The module to register
	 * @settings The module cbSecurity settings
	 */
	Security function registerModule( required string module, required struct settings ){
		// Param module settings
		param arguments.settings.firewall                             = {};
		param arguments.settings.firewall.invalidAuthenticationEvent  = "";
		param arguments.settings.firewall.defaultAuthenticationAction = "";
		param arguments.settings.firewall.invalidAuthorizationEvent   = "";
		param arguments.settings.firewall.defaultAuthorizationAction  = "";
		param arguments.settings.firewall.validator                   = "";
		param arguments.settings.firewall.rules                       = {};

		// Shorthand for rules
		if ( isArray( arguments.settings.firewall.rules ) ) {
			arguments.settings.firewall.rules = {
				inline   : arguments.settings.firewall.rules,
				defaults : {},
				provider : {}
			};
		}

		// Rule Defaults
		param arguments.settings.firewall.rules.defaults = {};
		param arguments.settings.firewall.rules.inline   = [];
		param arguments.settings.firewall.rules.provider = {};

		// Verify setting configurations
		variables.rulesLoader.rulesSourceChecks( arguments.settings.firewall.rules.provider );

		// Store configuration in this firewall
		variables.properties.securityModules[ arguments.module ] = arguments.settings;

		// Process Module Rules
		// Incorporate global defaults as well.
		if (
			isArray( arguments.settings.firewall.rules.inline ) && arrayLen(
				arguments.settings.firewall.rules.inline
			)
		) {
			arguments.settings.firewall.rules.inline = variables.rulesLoader.normalizeRules(
				rules   : arguments.settings.firewall.rules.inline,
				module  : module,
				defaults: arguments.settings.firewall.rules.defaults.append(
					variables.properties.firewall.rules.defaults,
					false
				)
			);
		}

		// Load Rules if we have a ruleSource
		if ( arguments.settings.firewall.rules.provider.source.len() ) {
			arguments.settings.firewall.rules.inline = variables.rulesLoader.loadRules(
				arguments.settings.firewall.rules.provider,
				arguments.settings.firewall.rules.defaults.append(
					variables.properties.firewall.rules.defaults,
					false
				)
			);
		}

		// prepend them so the don't interfere with MAIN rules
		// one by one as I don't see a way to prepend the whole array at once
		for ( var i = arguments.settings.firewall.rules.inline.len(); i >= 1; i-- ) {
			arrayPrepend(
				variables.properties.firewall.rules.inline,
				arguments.settings.firewall.rules.inline[ i ]
			);
		}

		// Log it
		log.info(
			"+ Registered module (#arguments.module#) with cbSecurity using #arrayLen( arguments.settings.firewall.rules.inline )# rules."
		);

		return this;
	}

	/**
	 * Listen to module loadings, so we can do module rule registrations
	 *
	 * @event        
	 * @interceptData
	 * @rc           
	 * @prc          
	 * @buffer       
	 */
	function postModuleLoad( event, interceptData, rc, prc, buffer ){
		// Is this a cbSecurity Module & not registered
		if (
			structKeyExists( arguments.interceptData.moduleConfig.settings, "cbSecurity" )
			&&
			!structKeyExists( variables.properties.securityModules, arguments.interceptData.moduleName )
		) {
			registerModule(
				arguments.interceptData.moduleName,
				arguments.interceptData.moduleConfig.settings.cbSecurity
			);
		}
	}

	/**
	 * Listen to module unloadings, so we can do module rule cleanups
	 *
	 * @event        
	 * @interceptData
	 * @rc           
	 * @prc          
	 * @buffer       
	 */
	function postModuleUnload( event, interceptData, rc, prc, buffer ){
		// Is the module registered?
		if ( structKeyExists( variables.properties.securityModules, arguments.interceptData.moduleName ) ) {
			// Delete registration
			structDelete( variables.properties.securityModules, arguments.interceptData.moduleName );
			// Delete rules
			variables.properties.firewall.rules.inline = variables.properties.firewall.rules.inline.filter( function( item ){
				return item.module != interceptData.moduleName;
			} );
			// Log it
			log.info( "- Unregistered module (#arguments.interceptData.moduleName#) with cbSecurity" );
		}
	}

	/**
	 * Our firewall kicks in at preProcess
	 *
	 * @event        
	 * @interceptData
	 * @rc           
	 * @prc          
	 * @buffer       
	 */
	function preProcess( event, interceptData, rc, prc, buffer ){
		// Add SecureView() into the requestcontext
		arguments.event.secureView = variables.cbSecurity.secureViewProxy;

		// Execute Rule Security
		if ( variables.properties.firewall.rules.inline.len() ) {
			processRules(
				arguments.event,
				arguments.interceptData,
				arguments.event.getCurrentEvent()
			);
		}

		// Execute Annotation Security
		if ( variables.properties.firewall.handlerAnnotationSecurity ) {
			processAnnotationRules(
				arguments.event,
				arguments.interceptData,
				arguments.event.getCurrentEvent()
			);
		}

		// Store User in ColdBox data bus
		try {
			variables.requestService
				.getContext()
				.setPrivateValue(
					variables.properties.authentication.prcUserVariable,
					variables.cbSecurity.getUser()
				);
		} catch ( "NoUserLoggedIn" e ) {
			// Skip it if we get this excecption, we just need the user in the prc bus!
		}
	}

	/**
	 * Process handler annotation based security rules.
	 *
	 * @event        
	 * @interceptData
	 * @currentEvent 
	 */
	function processAnnotationRules(
		required event,
		required interceptData,
		required currentEvent
	){
		// Get handler bean for the current event
		var handlerBean = variables.handlerService.getHandlerBean( arguments.event.getCurrentEvent() );

		// Are we running Coldbox 5 or older?
		// is an onInvalidHandlerBean configured?
		// is the current handlerBean the configured onInvalidEventHandlerBean?
		if (
			variables.enableInvalidHandlerCheck &&
			!isNull( variables.onInvalidEventHandlerBean ) &&
			isInvalidEventHandlerBean( handlerBean )
		) {
			// ColdBox tries to detect invalid event handler loops by keeping
			// track of the last invalid event to fire.  If that invalid event
			// fires twice, it throws a hard exception to prevent infinite loops.
			// Unfortunately for us, just attempting to get a handler bean
			// starts the invalid event handling.  Here, if we got the invalid
			// event handler bean back, we reset the `_lastInvalidEvent` so
			// ColdBox can handle the invalid event properly.
			request._lastInvalidEvent = variables.invalidEventHandler;
			return;
		}

		if ( handlerBean.getHandler() == "" ) {
			return;
		}

		// If metadata is not loaded, load it
		if ( !handlerBean.isMetadataLoaded() ) {
			variables.handlerService.getHandler( handlerBean, arguments.event );
		}

		// Verify we can access Handler
		var handlerResults = verifySecuredAnnotation(
			handlerBean.getHandlerMetadata( "secured", false ),
			arguments.event
		);
		if ( !handlerResults.allow ) {
			arguments.event.setPrivateValue( "cbSecurity_validatorResults", handlerResults );
			return processInvalidAnnotationAccess( arguments.event, handlerResults, "handler" );
		}

		if ( log.canDebug() ) {
			log.debug( "User handler annotation access succeeded", handlerResults );
		}

		// Verify we can access Action
		var actionResults = verifySecuredAnnotation(
			handlerBean.getActionMetadata( "secured", false ),
			arguments.event
		);
		if ( !actionResults.allow ) {
			arguments.event.setPrivateValue( "cbSecurity_validatorResults", actionResults );
			return processInvalidAnnotationAccess( arguments.event, actionResults, "action" );
		}

		// Final Log
		if ( log.canDebug() ) {
			log.debug( "User action annotation access succeeded" );
		}
	}

	/**
	 * Process handler or action metadata invalid access
	 *
	 * @event            The request context
	 * @validatorResults The validation results
	 * @type             The annotation type: handler|action
	 */
	private function processInvalidAnnotationAccess(
		required event,
		required validatorResults,
		required type
	){
		// Log Block
		if ( log.canWarn() ) {
			log.warn(
				"Invalid #arguments.validatorResults.type# by User (#variables.cbSecurity.getRealIp()#), blocked access to event=#arguments.event.getCurrentEvent()# via annotation (#arguments.type#) security"
			);
		}

		// Flash secured incoming URL for next request
		saveSecuredUrl( arguments.event );

		// Announce the block event
		var iData = {
			"ip"               : variables.cbSecurity.getRealIp(), // The offending IP
			"rule"             : {}, // An empty rule, since it is by annotation security
			"settings"         : getProperties(), // All the config settings, just in case
			"validatorResults" : arguments.validatorResults,
			"annotationType"   : arguments.type,
			"processActions"   : true // Boolean indicator if the invalid actions should process or not
		};
		announce( "cbSecurity_onInvalid#arguments.validatorResults.type#", iData );

		// Are we processing the invalid actions?
		if ( iData.processActions ) {
			processInvalidActions(
				rule  = rulesLoader.getRuleTemplate(),
				event = arguments.event,
				type  = arguments.validatorResults.type
			);
		}
		// end invalid actions processing
	}

	/**
	 * Process global and module security rules
	 *
	 * @event         Event object
	 * @interceptData Interception info
	 * @currentEvent  The possible event syntax to check
	 */
	function processRules(
		required event,
		required interceptData,
		required currentEvent
	){
		// Verify all rules
		for ( var thisRule in variables.properties.firewall.rules.inline ) {
			// Determine Match Target by event or url
			var matchTarget = (
				thisRule.match == "url" ? arguments.event.getCurrentRoutedURL() : arguments.currentEvent
			);

			// Are we in a whitelist?
			if ( isInPattern( matchTarget, thisRule.whitelist ) ) {
				if ( log.canDebug() ) {
					log.debug( "#matchTarget# found in whitelist: #thisRule.whitelist#, allowing access." );
				}

				variables.dbLogger.log(
					action   : "allow",
					blockType: "RULE-WHITELIST",
					ip       : variables.cbSecurity.getRealIp(),
					host     : variables.cbSecurity.getRealHost(),
					userId   : variables.cbSecurity.isLoggedIn() ? variables.cbSecurity.getUser().getId() : "",
					rule     : thisRule
				);
				continue;
			}

			// Are we in the secured list and in the rule's valid http methods and in the allowed Ips
			if ( isInPattern( matchTarget, thisRule.securelist ) ) {
				if ( log.canDebug() ) {
					log.debug( "---> Incoming '#matchTarget#' MATCHED this rule: #thisRule.toString()#" );
				}

				// Check authentication and authorizations
				var validatorResults = getValidator( arguments.event ).ruleValidator(
					thisRule,
					variables.controller
				);

				// Verify type, else default to "authentication"
				if ( !reFindNoCase( "(authentication|authorization|block)", validatorResults.type ) ) {
					validatorResults.type = "authentication";
				}

				// Verify IP or block
				if ( !isValidIP( thisRule.allowedIPs ) ) {
					validatorResults.type     = "authorization";
					validatorResults.allow    = false;
					validatorResults.messages = "Detected IP is not allowed";
				}

				// Verify HTTP Verbs or block
				if ( !isValidHTTPmethod( event, thisRule.httpMethods ) ) {
					validatorResults.type     = "authorization";
					validatorResults.allow    = false;
					validatorResults.messages = "Detected HTTP Method is not allowed";
				}

				// Do we allow or not?
				if ( !validatorResults.allow ) {
					// Log Block
					if ( log.canWarn() ) {
						log.warn(
							"Invalid #validatorResults.type# by (#variables.cbSecurity.getRealIp()#), blocked access to target=#matchTarget# using rule security: #thisRule.toString()#",
							validatorResults
						);
					}

					// Flash secured incoming URL for next request
					saveSecuredUrl( arguments.event );

					// Save the matched rule in the prc
					arguments.event
						.setPrivateValue( "cbSecurity_matchedRule", thisRule )
						.setPrivateValue( "cbSecurity_validatorResults", validatorResults );

					// Announce the block event
					var iData = {
						"ip"               : variables.cbSecurity.getRealIp(), // The offending IP
						"rule"             : thisRule, // The broken rule
						"validatorResults" : validatorResults,
						"settings"         : getProperties(), // All the config settings, just in case
						"annotationType"   : "",
						"processActions"   : true // Boolean indicator if the invalid actions should process or hard block
					};
					announce( "cbSecurity_onInvalid#validatorResults.type#", iData );

					// Are we processing the invalid actions or a hard block
					if ( iData.processActions ) {
						processInvalidActions(
							rule  = thisRule,
							event = arguments.event,
							type  = validatorResults.type
						);
					}
					break;
				}
				// end if valid state
				else {
					// Log it
					if ( log.canDebug() ) {
						log.debug(
							"Secure target=#matchTarget# matched and user authorized for rule: #thisRule.toString()#."
						);
					}
					break;
				}
			}
		}
		// end rule iterations
	}

	/**
	 * Register a validator object with this interceptor
	 *
	 * @validator The validator object to register
	 */
	function registerValidator( required validator ){
		if (
			structKeyExists( arguments.validator, "ruleValidator" )
			||
			structKeyExists( arguments.validator, "annotationValidator" )
		) {
			variables.validator = arguments.validator;
		} else {
			throw(
				message = "Validator object requires either a 'ruleValidator()' or `annotationValidator()' method. I can only register objects with these interface methods.",
				type    = "Security.ValidatorMethodException"
			);
		}
	}

	/**
	 * Get the global validator or if a module overrides it, use the module's validator
	 *
	 * @event The request context
	 */
	any function getValidator( required event = variables.requestService.getContext() ){
		// Check for module overrides
		var currentModule = arguments.event.getCurrentModule();
		if (
			// Are we in a module call?
			currentModule.len()
			&&
			// Does the module have cbSecurity overrides?
			structKeyExists( variables.properties.securityModules, currentModule )
			&&
			// Does the setting have value?
			variables.properties.securityModules[ currentModule ].firewall[ "validator" ].len()
		) {
			// Debug
			if ( log.canDebug() ) {
				log.debug(
					"validator setting overriden by #currentModule# module",
					variables.properties.securityModules[ currentModule ].firewall[ "validator" ]
				);
			}
			return variables.wirebox.getInstance(
				variables.properties.securityModules[ currentModule ].firewall[ "validator" ]
			);
		}

		return variables.validator;
	}

	/********************************* PRIVATE ******************************/

	/**
	 * Discover the invalid access property from either module -> global order.
	 *
	 * @property The property to discover
	 * @event    The request context
	 */
	private function discoverInvalidProperty( required property, required event ){
		// Check for module overrides
		var currentModule = arguments.event.getCurrentModule();
		if (
			// Are we in a module call?
			currentModule.len()
			&&
			// Does the module have cbSecurity overrides?
			structKeyExists( variables.properties.securityModules, currentModule )
			&&
			// Does the setting have value?
			variables.properties.securityModules[ currentModule ].firewall[ arguments.property ].len()
		) {
			// Debug
			if ( log.canDebug() ) {
				log.debug(
					"#arguments.property# setting overriden by #currentModule# module",
					variables.properties.securityModules[ currentModule ].firewall[ arguments.property ]
				);
			}
			return variables.properties.securityModules[ currentModule ].firewall[ arguments.property ];
		}

		// Debug
		if ( log.canDebug() ) {
			log.debug(
				"Using global #arguments.property# setting",
				variables.properties.firewall[ arguments.property ]
			);
		}

		// Return global property
		return variables.properties.firewall[ arguments.property ];
	}

	/**
	 * Verifies if a user is authorized according to the incoming secured value annotation.
	 * If we return true, it means that the user has validated, false means they are not authorized
	 *
	 * @securedValue The secured value annotation
	 * @event        The request context
	 *
	 * @return { allow:boolean, type:string(authentication|authorization)}
	 */
	private struct function verifySecuredAnnotation( required securedValue, required event ){
		// Are we securing?
		if ( len( arguments.securedValue ) && isBoolean( arguments.securedValue ) && !arguments.securedValue ) {
			return { "allow" : true, "type" : "authentication" }; // we can access
		}

		// Now call the validator and pass in the secured value
		var validatorResults = getValidator( arguments.event ).annotationValidator(
			arguments.securedValue,
			variables.controller
		);

		// Verify type, else default to "authentication"
		if ( !reFindNoCase( "(authentication|authorization)", validatorResults.type ) ) {
			validatorResults.type = "authentication";
		}

		return validatorResults;
	}

	/**
	 * Process invalid actions on a rule
	 *
	 * @rule  The offending rule
	 * @event The request context
	 * @type  The invalid type: authentication or authorization
	 */
	private function processInvalidActions( required rule, required event, required type ){
		// Discover action, from specific (rule) to global setting
		var defaultAction = (
			arguments.rule.action.len() ? arguments.rule.action : discoverInvalidProperty(
				"default#arguments.type#Action",
				arguments.event
			)
		);
		// Discover relocation, from specific (rule) to global setting
		var redirectEvent = (
			arguments.rule.redirect.len() ? arguments.rule.redirect : discoverInvalidProperty(
				"invalid#arguments.type#Event",
				arguments.event
			)
		);
		// Discover override, from specific (rule) to global setting
		var overrideEvent = (
			arguments.rule.overrideEvent.len() ? arguments.rule.overrideEvent : discoverInvalidProperty(
				"invalid#arguments.type#Event",
				arguments.event
			)
		);

		// Now let's check if a rule has individual redirect or overrideEvent elements
		if ( arguments.rule.overrideEvent.len() ) {
			defaultAction = "override";
		}
		if ( arguments.rule.redirect.len() ) {
			defaultAction = "redirect";
		}

		// Debug
		if ( log.canDebug() ) {
			log.debug( "Processing a #defaultAction# due to an invalid #arguments.type#" );
		}

		variables.dbLogger.log(
			action   : defaultAction,
			blockType: arguments.type,
			ip       : variables.cbSecurity.getRealIp(),
			host     : variables.cbSecurity.getRealHost(),
			userId   : variables.cbSecurity.isLoggedIn() ? variables.cbSecurity.getUser().getId() : "",
			rule     : arguments.rule
		);

		// Determine actions from rules
		switch ( defaultAction ) {
			case "redirect": {
				// Double check for length else give warning
				if ( !redirectEvent.len() ) {
					throw(
						message = "The redirect action is empty, either add a redirect to the rule or a global Invalid#arguments.type#Event setting",
						type    = "InvalidAccessAction"
					);
				}
				// Are we relocating to an event or to an http? location
				if ( reFindNoCase( "^http?:", redirectEvent ) ) {
					// Relocate now
					relocate(
						URL     = redirectEvent,
						persist = "_securedURL",
						// Chain SSL: Global, rule, request
						ssl     = (
							variables.properties.firewall.rules.useSSL || arguments.rule.useSSL || arguments.event.isSSL()
						)
					);
				} else {
					// Relocate now
					relocate(
						event   = redirectEvent,
						persist = "_securedURL",
						// Chain SSL: Global, rule, request
						ssl     = (
							variables.properties.firewall.rules.useSSL || arguments.rule.useSSL || arguments.event.isSSL()
						)
					);
				}

				break;
			}

			case "override": {
				// Double check for length else give warning
				if ( !overrideEvent.len() ) {
					throw(
						message = "The override event action is empty, either add a redirect to the rule or a global Invalid#arguments.type#Event setting",
						type    = "InvalidAccessAction"
					);
				}
				// Override event
				arguments.event.overrideEvent( event = overrideEvent );
				break;
			}

			case "block": {
				arguments.event
					.renderData(
						data       = "<h1>Unathorized</h1>",
						statusCode = "401",
						statusText = "Unathorized"
					)
					.noExecution();
				break;
			}

			default: {
				throw(
					message = "The type [#defaultAction#] is not a valid rule action.  Valid types are [ 'redirect', 'override', 'block' ].",
					type    = "InvalidRuleActionType"
				);
			}
		}
	}

	/**
	 * Flash the incoming secured Url so we can redirect to it or use it in the next request.
	 *
	 * @event The event object
	 */
	private function saveSecuredUrl( required event ){
		var securedUrl = arguments.event.getFullUrl();

		if ( arguments.event.isSES() ) {
			securedURL = arguments.event.buildLink(
				to          = event.getCurrentRoutedURL(),
				queryString = CGI.QUERY_STRING,
				translate   = false
			);
		}

		// Flash it and place it in RC as well
		flash.put( "_securedUrl", securedUrl );
		arguments.event.setValue( "_securedUrl", securedUrl );
	}

	/**
	 * Verifies that the current event is in a given pattern list
	 *
	 * @currentEvent The current event
	 * @patternList  The list pattern to test
	 */
	private boolean function isInPattern( required currentEvent, required patternList ){
		//  Loop Over Patterns
		for ( var pattern in arguments.patternList ) {
			//  Using Regex
			if ( variables.properties.firewall.rules.useRegex ) {
				if ( reFindNoCase( trim( pattern ), arguments.currentEvent ) ) {
					return true;
				}
			} else if ( findNoCase( trim( pattern ), arguments.currentEvent ) ) {
				return true;
			}
		}

		return false;
	}

	/**
	 * Verifies that the current request's http method is valid for execution
	 *
	 * @event       The request context
	 * @httpMethods The httpMethods from the rule to verify
	 */
	private boolean function isValidHTTPmethod( required event, required httpMethods ){
		// Nothing or ALL
		if ( !len( arguments.httpMethods ) || arguments.httpMethods == "*" ) {
			return true;
		}
		// Else we need to test the verb list
		return listFindNoCase( arguments.httpMethods, arguments.event.getHTTPMethod() );
	}

	/**
	 * Verifies that the current request's IP is valid for execution
	 *
	 * @allowedIPs The allowedIPs in the rule
	 */
	private boolean function isValidIP( required allowedIPs ){
		// Nothing or ALL
		if ( !len( arguments.allowedIPs ) || arguments.allowedIPs == "*" ) {
			return true;
		}
		// Else we need to test the ip list against the actual IP
		return listFindNoCase( arguments.allowedIPs, variables.cbSecurity.getRealIP() );
	}

	/**
	 * Returns true of the passed handlerBean matches Coldbox's configured invalid event handler.
	 *
	 * @handlerBean the current handler bean to check against
	 */
	private boolean function isInvalidEventHandlerBean( required handlerBean ){
		return (
			variables.onInvalidEventHandlerBean.getInvocationPath() == arguments.handlerBean.getInvocationPath() &&
			variables.onInvalidEventHandlerBean.getHandler() == arguments.handlerBean.getHandler() &&
			variables.onInvalidEventHandlerBean.getMethod() == arguments.handlerBean.getMethod() &&
			variables.onInvalidEventHandlerBean.getModule() == arguments.handlerBean.getModule()
		);
	}

}
