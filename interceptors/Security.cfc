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
	 * Configure the interception
	 */
	function configure(){
		// default to false
		variables.initialized = false;

		// Rule Source Checks
		if ( !getProperty( "rulesSource" ).len() ) {
			throw(
				message = "The <code>ruleSource</code> property has not been set.",
				type 	= "Security.NoRuleSourceDefined"
			);
		}
		if ( !reFindNoCase( "^(xml|db|model|json)$", getProperty( "rulesSource" ) ) ) {
			throw(
				message = "The rules source you set is invalid: #getProperty( "rulesSource" )#.",
				detail 	= "The valid sources are xml, db, model, or json",
				type 	= "Security.InvalidRuleSource"
			);
		}

		// PreEvent Security
		if ( not propertyExists( "preEventSecurity" ) or not isBoolean( getProperty( "preEventSecurity" ) ) ) {
			setProperty( "preEventSecurity", false );
		}

		// Verify rule configurations
		rulesSourceChecks();

		// Setup the rules to empty
		setProperty( "rules", [] );
	}

	/**
	 * Once the application has loaded, we then proceed to setup the rule engine
	 *
	 * @event
	 * @interceptData
	 * @rc
	 * @prc
	 * @buffer
	 */
	function afterAspectsLoad(
		event,
		interceptData,
		rc,
		prc,
		buffer
	){
		// if no preEvent, then unregister yourself.
		if ( !getProperty( "preEventSecurity" ) ) {
			unregister( "preEvent" );
		}

		// Load Rules
		setProperty(
			"rules",
			getInstance( "RulesLoader@cbSecurity" ).loadRules( getProperties() )
		);

		// Load up the validator
		if ( getProperty( "validator" ).len() ) {
			registerValidator(
				getInstance( getProperty( "validator" ) )
			);
		}

		// We can now rule!
		variables.initialized = true;
	}

	/**
	 * Listen to event preProcessing
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
		// Check if inited already
		if ( NOT variables.initialized ) {
			afterAspectsLoad( arguments.event, arguments.interceptData );
		}

		// Execute Rule processing
		processRules( arguments.event, arguments.interceptData, arguments.event.getCurrentEvent() );
	}

	/**
	 * Listen to before any runEvent()'s
	 *
	 * @event
	 * @interceptData
	 * @rc
	 * @prc
	 * @buffer
	 */
	function preEvent(
		event,
		interceptData,
		rc,
		prc,
		buffer
	){
		if ( getProperty( "preEventSecurity" ) ) {
			processRules( arguments.event, arguments.interceptData, arguments.interceptData.processedEvent );
		}
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
		var x = 1;
		var rules = getProperty( "rules" );
		var rulesLen = arrayLen( rules );
		var rc = event.getCollection();
		var ssl = getProperty( "useSSL" );
		var matchType = "event";
		var matchTarget = "";

		// Loop through Rules
		for ( x = 1; x lte rulesLen; x = x + 1 ) {
			// Determine match type and if event or url, the valid types
			if ( structKeyExists( rules[ x ], "match" ) AND reFindNoCase( "^(event|url)$", rules[ x ].match ) ) {
				matchType = rules[ x ].match;
			}
			// According to type get the matchTarget
			if ( matchType eq "event" ) {
				matchTarget = arguments.currentEvent;
			} else{
				matchTarget = arguments.event.getCurrentRoutedURL();
			}

			// is current matchTarget in this whitelist pattern? then continue to next rule
			if ( isInPattern( matchTarget, rules[ x ].whitelist ) ) {
				if ( log.canDebug() ) {
					log.debug( "'#matchTarget#' found in whitelist: #rules[ x ].whitelist#" );
				}
				continue;
			}

			// is match in the secure list and is user in role
			if ( isInPattern( matchTarget, rules[ x ].securelist ) ) {
				// Verify if user is logged in and in a secure state
				if ( _isUserInValidState( rules[ x ] ) eq false ) {
					// Log if Necessary
					if ( log.canDebug() ) {
						log.debug(
							"User did not validate security for secured match target=#matchTarget#. Rule: #rules[ x ].toString()#"
						);
					}

					// Redirect
					if ( arguments.event.isSES() ) {
						// Save the secured URL
						rc._securedURL = arguments.event.buildLink( event.getCurrentRoutedURL() );
					} else{
						// Save the secured URL
						rc._securedURL = "#cgi.script_name#";
					}

					// Check query string for secure URL
					if ( cgi.query_string neq "" ) {
						rc._securedURL = rc._securedURL & "?#cgi.query_string#";
					}

					// SSL?
					if ( structKeyExists( rules[ x ], "useSSL" ) ) {
						ssl = rules[ x ].useSSL;
					}

					// Route to redirect event
					setNextEvent( event = rules[ x ].redirect, persist = "_securedURL", ssl = ssl );

					break;
				}
				// end user in roles
				else{
					if ( log.canDebug() ) {
						log.debug(
							"Secure target=#matchTarget# matched and user validated for rule: #rules[ x ].toString()#."
						);
					}
					break;
				}
			}
			// end if current event did not match a secure event.
			else{
				if ( log.canDebug() ) {
					log.debug( "Incoming '#matchTarget#' did not match this rule: #rules[ x ].toString()#" );
				}
			}
		}
		// end of rules checks
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

	/**
	 * Verifies that the user is in any role
	 *
	 * @validatorObject
	 */
	function _isUserInValidState( required struct rule ){
		var thisRole = "";
		//  Verify if using validator
		if ( isValidatorUsed() ) {
			//  Validate via Validator
			return variables.validator.userValidator( arguments.rule, controller );
		}
		//  Loop Over CF Roles
		for ( thisRole in arguments.rule.roles ) {
			if ( isUserInRole( thisRole ) ) {
				return true;
			}
		}
		return false;
	}

	/**
	 * Verifies that the current event is in a given pattern list
	 *
	 * @currentEvent The current event
	 * @patternList The list pattern to test
	 */
	function isInPattern( required currentEvent, required patternList ){
		var pattern = "";
		//  Loop Over Patterns
		for ( pattern in arguments.patternList ) {
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
	 * Check to see if using the validator
	 */
	boolean function isValidatorUsed(){
		return !isNull( variables.validator );
	}

	/********************************* PRIVATE ******************************/

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

}