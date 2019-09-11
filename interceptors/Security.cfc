/**
 * Copyright since 2016 by Ortus Solutions, Corp
 * www.ortussolutions.com
 * ---
 * This interceptor provides security to an application. It is very flexible and customizable.
 * It bases off on the ability to secure events by creating rules or annotations on your handlers
 * This interceptor will then try to match a rule to the incoming event and the user's credentials on roles and/or permissions.
 */
component accessors="true" extends="coldbox.system.Interceptor" {

	/**
	 * Is the listener initialized
	 */
	property name="initialized" type="boolean";

	/**
	 * The reference to the security validator for this interceptor
	 */
	property name="validator";

	/**
	 * Configure the security firewall
	 */
	function configure(){
		// Rule Source Checks
		if ( getProperty( "rulesSource" ).len() && !reFindNoCase( "^(xml|db|model|json)$", getProperty( "rulesSource" ) ) ) {
			throw(
				message = "The rules source you set is invalid: #getProperty( "rulesSource" )#.",
				detail 	= "The valid sources are xml, db, model, or json",
				type 	= "Security.InvalidRuleSource"
			);
		}

		// Verify rule configurations
		rulesSourceChecks();

		// Load up the rules if needed
		var rulesLoader = getInstance( "RulesLoader@cbSecurity" );

		// If we added our own rules, then normalize them.
		if( arrayLen( getProperty( "rules" ) ) ){
			setProperty( "rules", rulesLoader.normalizeRules( getProperty( "rules" ) ) );
		}

		// Load Rules if we have a ruleSource
		if( getProperty( "rulesSource" ).len() ){
			setProperty( "rules", rulesLoader.loadRules( getProperties() ) );
		}

		// Load up the validator
		registerValidator(
			getInstance( getProperty( "validator" ) )
		);
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
		// If an HTTP Verb is OPTIONS then bail, no need to secure.
		if ( event.getHTTPMethod() == "OPTIONS" ) {
            return;
		}

		// Execute Rule processing
		processRules(
			arguments.event,
			arguments.interceptData,
			arguments.event.getCurrentEvent()
		);
	}

	/**
	 * Process security rules. This method is called from an interception point
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
				if ( !_isUserInValidState( thisRule ) ) {

					// Log Block
					if ( log.canWarn() ) {
						log.warn(
							"User (#getRealIp()#) blocked access to target=#matchTarget#. Rule: #thisRule.toString()#"
						);
					}

					// Flash secured incoming URL for next request
					saveSecuredUrl( arguments.event );

					// Announce the block event
					var iData = {
						"ip" 				: getRealIp(), // The offending IP
						"rule" 				: thisRule, // The broken rule
						"settings"			: getProperties(), // All the config settings, just in case
						"processActions" 	: true // Boolean indicator if the invalid actions should process or not
					};
					announceInterception( state="cbSecurity_onInvalidAccess", interceptData=iData );

					// Are we processing the invalid actions?
					if( iData.processActions ){
						processInvalidActions( thisRule, arguments.event );
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
		if ( structKeyExists( arguments.validator, "userValidator" ) ) {
			variables.validator = arguments.validator;
		} else{
			throw(
				message = "Validator object does not have a 'userValidator' method, I can only register objects with this interface method.",
				type 	= "Security.ValidatorMethodException"
			);
		}
	}

	/********************************* PRIVATE ******************************/

	/**
	 * Process invalid actions on a rule
	 *
	 * @rule The offending rule
	 * @event The request context
	 */
	private function processInvalidActions( required rule, required event ){
		// Discover relocation, from specific (rule) to global setting
		var redirectEvent = ( arguments.rule.redirect.len() ? arguments.rule.redirect : getProperty( "invalidAccessRedirect" ) );
		// Discover override, from specific (rule) to global setting
		var overrideEvent = ( arguments.rule.overrideEvent.len() ? arguments.rule.overrideEvent : getProperty( "invalidAccessOverrideEvent" ) );
		// Discover action, from specific (rule) to global setting
		var defaultAction = ( arguments.rule.action.len() ? arguments.rule.action : getProperty( "defaultInvalidAction" ) );

		// Now let's check if a rule has individual redirect or overrideEvent elements
		if( arguments.rule.overrideEvent.len() ){
			defaultAction = "override";
		}
		if( arguments.rule.redirect.len() ){
			defaultAction = "redirect";
		}

		// Determine actions from rules
		switch( defaultAction ){
			case "redirect" : {
				// Double check for length else give warning
				if( !redirectEvent.len() ){
					throw(
						message = "The redirect action is empty, either add a redirect to the rule or a global InvalidAccessRedirect setting",
						type 	= "InvalidAccessAction"
					);
				}
				// Relocate now
				relocate(
					event 	= redirectEvent,
					persist = "_securedURL",
					// Chain SSL: Global, rule, request
					ssl 	= ( getProperty( "useSSL" ) || arguments.rule.useSSL || arguments.event.isSSL() )
				);
				break;
			}
			case "override" : {
				// Double check for length else give warning
				if( !overrideEvent.len() ){
					throw(
						message = "The override event action is empty, either add a redirect to the rule or a global invalidAccessOverrideEvent setting",
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
	 * Verifies that the user is in any role using the validator
	 *
	 * @rule The rule to validate
	 */
	private function _isUserInValidState( required struct rule ){
		//  Validate via Validator
		return variables.validator.userValidator( arguments.rule, variables.controller );
	}

	/**
	 * Verifies that the current event is in a given pattern list
	 *
	 * @currentEvent The current event
	 * @patternList The list pattern to test
	 */
	private function isInPattern( required currentEvent, required patternList ){

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
	 * Validate the rules source property
	 */
	private function rulesSourceChecks(){
		switch ( getProperty( "rulesSource" ) ) {
			case "xml":
			case "json": {
				// Check if file property exists
				if ( !getProperty( "rulesFile" ).len() ) {
					throw(
						message = "Please enter a valid rulesFile setting",
						type 	= "Security.RulesFileNotDefined"
					);
				}
				break;
			}

			case "db": {
				if ( !getProperty( "rulesDSN" ).len() ) {
					throw(
						message = "Missing setting for DB source: rulesDSN ",
						type 	= "Security.RuleDSNNotDefined"
					);
				}
				if ( !getProperty( "rulesTable" ).len() ) {
					throw(
						message = "Missing setting for DB source: rulesTable ",
						type 	= "Security.RulesTableNotDefined"
					);
				}
				break;
			}

			case "model": {
				if ( !getProperty( "rulesModel" ).len() ) {
					throw(
						message = "Missing setting for model source: rulesModel ",
						type 	= "Security.RulesModelNotDefined"
					);
				}

				break;
			}
		}
		// end of switch statement
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