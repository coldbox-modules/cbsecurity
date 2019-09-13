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
	property name="rulesLoader" 	inject="rulesLoader@cbSecurity";
	property name="handlerService" 	inject="coldbox:handlerService";

	/**
	 * The reference to the security validator for this interceptor
	 */
	property name="validator";

	/**
	 * A map of registered modules that leverage cbSecurity rules
	 */
	property name="securityModules" type="struct";

	/**
	 * Configure the security firewall
	 */
	function configure(){

		// init the security modules dictionary
		variables.securityModules = {};

		// Verify setting configurations
		variables.rulesLoader.rulesSourceChecks( getProperties() );

		// If we added our own rules, then normalize them.
		if( arrayLen( getProperty( "rules" ) ) ){
			setProperty( "rules", variables.rulesLoader.normalizeRules( getProperty( "rules" ) ) );
		}

		// Load Rules if we have a ruleSource
		if( getProperty( "rulesSource" ).len() ){
			setProperty( "rules", variables.rulesLoader.loadRules( getProperties() ) );
		}

		// Load up the validator
		registerValidator(
			getInstance( getProperty( "validator" ) )
		);
	}

	/**
	 * Listen when modules are activated to load their cbSecurity capabilities
	 */
	function afterAspectsLoad(
		event,
		interceptData,
		rc,
		prc,
		buffer
	){
		// Register cbSecurity modules so we can incorporate them.
		controller
			.getSetting( "modules" )
			// Discover cbSecurity modules
			.filter( function( module, config ){
				return (
					arguments.config.settings.keyExists( "cbSecurity" )
					&&
					!structKeyExists( variables.securityModules, arguments.module )
				);
			} )
			// Register module settings
			.each( function( module, config ){
				// Register Module
				registerModule( arguments.module, arguments.config.settings.cbSecurity );
			} );
	}

	/**
	 * Register a module with cbSecurity by passing it's name and the cbSecurity settings struct
	 *
	 * @module The module to register
	 * @settings The module cbSecurity settings
	 */
	Security function registerModule( required string module, required struct settings ){
		// Param settings
		param arguments.settings.rules 							= [];
		param arguments.settings.invalidAuthenticationEvent 	= "";
		param arguments.settings.defaultAuthenticationAction 	= "";
		param arguments.settings.invalidAuthorizationEvent 		= "";
		param arguments.settings.defaultAuthorizationAction 	= "";

		// Store configuration in this firewall
		variables.securityModules[ arguments.module ] = arguments.settings;

		// Process Module Rules
		arguments.settings.rules = variables.rulesLoader.normalizeRules( arguments.settings.rules, module );

		// Append them
		arrayAppend( getProperty( "rules" ), arguments.settings.rules, true );

		// Log it
		log.info( "+ Registered module (#arguments.module#) with cbSecurity" );

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
	function postModuleLoad(
		event,
		interceptData,
		rc,
		prc,
		buffer
	){
		// Is this a cbSecurity Module & not registered
		if(
			structKeyExists( arguments.interceptData.moduleConfig.settings, "cbSecurity" )
			&&
			!structKeyExists( variables.securityModules, arguments.interceptData.moduleName )
		){
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
	function postModuleUnload(
		event,
		interceptData,
		rc,
		prc,
		buffer
	){
		// Is the module registered?
		if( structKeyExists( variables.securityModules, arguments.interceptData.moduleName ) ){
			// Delete registration
			structDelete( variables.securityModules, arguments.interceptData.moduleName );
			// Delete rules
			setProperty(
				"rules",
				getProperty( "rules" )
					.filter( function( item ){
						return item.module != interceptData.moduleName;
					} )
			);
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
	function preProcess(
		event,
		interceptData,
		rc,
		prc,
		buffer
	){
		// Execute Rule processing
		if( getProperty( "rules" ).len() ){
			processRules(
				arguments.event,
				arguments.interceptData,
				arguments.event.getCurrentEvent()
			);
		}

		// Are we doing annotation based security?
		if( getProperty( "handlerAnnotationSecurity" ) ){
			processAnnotationRules(
				arguments.event,
				arguments.interceptData,
				arguments.event.getCurrentEvent()
			);
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
        if ( handlerBean.getHandler() == "" ) {
            return;
		}

		// If metadata is not loaded, load it
        if ( ! handlerBean.isMetadataLoaded() ) {
            handlerService.getHandler( handlerBean, arguments.event );
		}

		// Verify we can access Handler
		var handlerResults = verifySecuredAnnotation(
			handlerBean.getHandlerMetadata( "secured", false ),
			arguments.event
		);
		if( ! handlerResults.allow ){
			return processInvalidAccess( arguments.event, handlerResults, "handler" );
		}

		// Verify we can access Action
		var actionResults = verifySecuredAnnotation(
			handlerBean.getActionMetadata( "secured", false ),
			arguments.event
		);
		if( !actionResults.allow ){
			return processInvalidAccess( arguments.event, actionResults, "action" );
		}

		// Final Log
		if ( log.canDebug() ) {
			log.debug( "User access granted, annotation security passed" );
		}
	}

	/**
	 * Process handler or action metadata invalid access
	 *
	 * @event The request context
	 * @validatorResults The validation results
	 * @type The annotation type: handler|action
	 */
	private function processInvalidAccess( required event, required validatorResults, required type ){

		// Log Block
		if ( log.canWarn() ) {
			log.warn(
				"Invalid #arguments.validatorResults.type# by User (#getRealIp()#), blocked access to event=#arguments.event.getCurrentEvent()# via annotation security"
			);
		}

		// Flash secured incoming URL for next request
		saveSecuredUrl( arguments.event );

		// Announce the block event
		var iData = {
			"ip" 				: getRealIp(), // The offending IP
			"rule" 				: {}, // An empty rule, since it is by annotation security
			"settings"			: getProperties(), // All the config settings, just in case
			"validatorResults"	: arguments.validatorResults,
			"annotationType"	: arguments.type,
			"processActions" 	: true // Boolean indicator if the invalid actions should process or not
		};
		announceInterception( state="cbSecurity_onInvalid#arguments.validatorResults.type#", interceptData=iData );

		// Are we processing the invalid actions?
		if( iData.processActions ){
			processInvalidActions(
				rule	= rulesLoader.getRuleTemplate(),
				event	= arguments.event,
				type	= arguments.validatorResults.type
			);
		} // end invalid actions processing

	}

	/**
	 * Process global and module security rules
	 *
	 * @event Event object
	 * @interceptData Interception info
	 * @currentEvent The possible event syntax to check
	 */
	function processRules(
		required event,
		required interceptData,
		required currentEvent
	){
		// Verify all rules
		for( var thisRule in getProperty( "rules" ) ){
			// Determine Match Target by event or url
			var matchTarget = ( thisRule.match == "url" ? arguments.event.getCurrentRoutedURL() : arguments.currentEvent );

			// Are we in a whitelist?
			if ( isInPattern( matchTarget, thisRule.whitelist ) ) {
				if ( log.canDebug() ) {
					log.debug( "#matchTarget# found in whitelist: #thisRule.whitelist#, allowing access." );
				}
				continue;
			}

			// Are we in the secured list?
			if ( isInPattern( matchTarget, thisRule.securelist ) ) {

				// Verify if user is logged in and in a secure state
				var validatorResults = getValidator().ruleValidator( thisRule, variables.controller );
				// Verify type, else default to "authentication"
				if( !reFindNoCase( "(authentication|authorization)", validatorResults.type ) ){
					validatorResults.type = "authentication";
				}

				// Do we allow or not?
				if ( !validatorResults.allow  ) {

					// Log Block
					if ( log.canWarn() ) {
						log.warn(
							"Invalid #validatorResults.type# by User (#getRealIp()#), blocked access to target=#matchTarget# using rule security: #thisRule.toString()#"
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
						"ip" 				: getRealIp(), // The offending IP
						"rule" 				: thisRule, // The broken rule
						"validatorResults"	: validatorResults,
						"settings"			: getProperties(), // All the config settings, just in case
						"annotationType"	: "",
						"processActions" 	: true // Boolean indicator if the invalid actions should process or not
					};
					announceInterception( state="cbSecurity_onInvalid#validatorResults.type#", interceptData=iData );

					// Are we processing the invalid actions?
					if( iData.processActions ){
						processInvalidActions( rule=thisRule, event=arguments.event, type=validatorResults.type );
					} // end invalid actions processing

					break;
				}
				// end if valid state
				else{
					if ( log.canDebug() ) {
						log.debug(
							"Secure target=#matchTarget# matched and user authorized for rule: #thisRule.toString()#."
						);
					}
					break;
				}
			}
			// No match, continue to next rule
			else{
				if ( log.canDebug() ) {
					log.debug( "Incoming '#matchTarget#' did not match this rule: #thisRule.toString()#" );
				}
			}

		} // end rule iterations
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
		} else{
			throw(
				message = "Validator object does not have a 'userValidator()' and `annotationValidator()' methods. I can only register objects with these interface methods.",
				type 	= "Security.ValidatorMethodException"
			);
		}
	}

	/********************************* PRIVATE ******************************/

	/**
	 * Discover the invalid access property from either module -> global order.
	 *
	 * @property The property to discover
	 * @event The request context
	 */
	private function discoverInvalidProperty( required property, required event ){
		// Check for module overrides
		var currentModule = arguments.event.getCurrentModule();
		if (
			// Are we in a module call?
			currentModule.len()
			&&
			// Does the module have cbSecurity overrides?
			structKeyExists( variables.securityModules, currentModule )
			&&
			// Does the setting have value?
			variables.securityModules[ currentModule ][ arguments.property ].len()
		) {
			// Debug
			if ( log.canDebug() ) {
				log.debug(
					"#arguments.property# setting overriden by #currentModule# module",
					variables.securityModules[ currentModule ][ arguments.property ]
				);
			}
			return variables.securityModules[ currentModule ][ arguments.property ];
		}

		// Debug
		if ( log.canDebug() ) {
			log.debug(
				"Using global #arguments.property# setting",
				getProperty( arguments.property )
			);
		}

		// Return global property
		return getProperty( arguments.property );
	}

	/**
	 * Verifies if a user is authorized according to the incoming secured value annotation.
	 * If we return true, it means that the user has validated, false means they are not authorized
	 *
	 * @securedValue The secured value annotation
	 *
	 * @return { allow:boolean, type:string(authentication|authorization)}
	 */
	private struct function verifySecuredAnnotation( required securedValue ){
		// If no value, then default it to true
		if( !len( arguments.securedValue ) ){ arguments.securedValue = true; }

		// Are we securing?
		if( isBoolean( arguments.securedValue ) && !arguments.securedValue ){
			return { "allow" : true, "type" : "authentication" }; // we can access
		}

		// Now call the user validator and pass in the secured value
		var validatorResults = getValidator().annotationValidator( arguments.securedValue, variables.controller );

		// Verify type, else default to "authentication"
		if( !reFindNoCase( "(authentication|authorization)", validatorResults.type ) ){
			validatorResults.type = "authentication";
		}
		return validatorResults;
	}

	/**
	 * Process invalid actions on a rule
	 *
	 * @rule The offending rule
	 * @event The request context
	 * @type The invalid type: authentication or authorization
	 */
	private function processInvalidActions( required rule, required event, required type ){
		// Discover action, from specific (rule) to global setting
		var defaultAction = ( arguments.rule.action.len() ? arguments.rule.action : discoverInvalidProperty( "default#arguments.type#Action", arguments.event ) );
		// Discover relocation, from specific (rule) to global setting
		var redirectEvent = ( arguments.rule.redirect.len() ? arguments.rule.redirect : discoverInvalidProperty( "invalid#arguments.type#Event", arguments.event ) );
		// Discover override, from specific (rule) to global setting
		var overrideEvent = ( arguments.rule.overrideEvent.len() ? arguments.rule.overrideEvent : discoverInvalidProperty( "invalid#arguments.type#Event", arguments.event ) );

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

		// Determine actions from rules
		switch( defaultAction ){
			case "redirect" : {
				// Double check for length else give warning
				if( !redirectEvent.len() ){
					throw(
						message = "The redirect action is empty, either add a redirect to the rule or a global Invalid#arguments.type#Event setting",
						type 	= "InvalidAccessAction"
					);
				}
				// Are we relocating to an event or to an http? location
				if( reFindNoCase( "^http?:", redirectEvent ) ){
					// Relocate now
					relocate(
						URL 	= redirectEvent,
						persist = "_securedURL",
						// Chain SSL: Global, rule, request
						ssl 	= ( getProperty( "useSSL" ) || arguments.rule.useSSL || arguments.event.isSSL() )
					);
				} else {
					// Relocate now
					relocate(
						event 	= redirectEvent,
						persist = "_securedURL",
						// Chain SSL: Global, rule, request
						ssl 	= ( getProperty( "useSSL" ) || arguments.rule.useSSL || arguments.event.isSSL() )
					);
				}

				break;
			}

			case "override" : {
				// Double check for length else give warning
				if( !overrideEvent.len() ){
					throw(
						message = "The override event action is empty, either add a redirect to the rule or a global Invalid#arguments.type#Event setting",
						type 	= "InvalidAccessAction"
					);
				}
				// Override event
				arguments.event.overrideEvent( event=overrideEvent );
				break;
			}

			default : {
				throw(
					message = "The type [#defaultAction#] is not a valid rule action.  Valid types are [ 'redirect', 'override' ].",
					type 	= "InvalidRuleActionType"
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
				to 			= event.getCurrentRoutedURL(),
				queryString = CGI.QUERY_STRING,
				translate 	= false
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
	 * @patternList The list pattern to test
	 */
	private boolean function isInPattern( required currentEvent, required patternList ){

		//  Loop Over Patterns
		for ( var pattern in arguments.patternList ) {
			//  Using Regex
			if ( getProperty( "useRegex" ) ) {
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
	 * Get Real IP, by looking at clustered, proxy headers and locally.
	 */
	private function getRealIP(){
		var headers = getHttpRequestData().headers;

		// Very balanced headers
		if( structKeyExists( headers, 'x-cluster-client-ip' ) ){
			return headers[ 'x-cluster-client-ip' ];
		}
		if( structKeyExists( headers, 'X-Forwarded-For' ) ){
			return headers[ 'X-Forwarded-For' ];
		}

		return len( CGI.REMOTE_ADDR ) ? CGI.REMOTE_ADDR : '127.0.0.1';
	}

}