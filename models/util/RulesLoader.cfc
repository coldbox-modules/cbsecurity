/**
 * Copyright since 2016 by Ortus Solutions, Corp
 * www.ortussolutions.com
 * ---
 * Rule loader service
 */
component accessors="true" singleton threadsafe {

	// DI
	property name="controller" inject="coldbox";
	property name="wirebox" inject="wirebox";

	/**
	 * Constructor
	 */
	function init(){
		return this;
	}

	/**
	 * Utility function to normalize an array of rules to our standards
	 *
	 * @rules The rules to normalize
	 * @module The module to incorporate if passed
	 */
	array function normalizeRules( required array rules, module = "" ){
		return arguments.rules.map( function( item ){
			// Append template
			structAppend( item, getRuleTemplate(), false );
			// Incorporate module if needed
			item.module = module;
			return item;
		} );
	}

	/**
	 * Load the appropriate rules from the source and return them in consumable focus.
	 *
	 * @settings The interceptor config settings
	 */
	array function loadRules( required settings ){
		// Load Rules
		switch ( arguments.settings.rulesSource ) {
			case "xml": {
				return loadXMLRules( arguments.settings );
			}
			case "json": {
				return loadJSONRules( arguments.settings );
			}
			case "db": {
				return loadDBRules( arguments.settings );
			}
			case "model": {
				return loadModelRules( arguments.settings );
			}
		}
	}

	/**
	 * Validate the rules source property
	 *
	 * @settings The settings to check
	 */
	function rulesSourceChecks( required settings ){
		param arguments.settings.rulesSource = "";
		param arguments.settings.rules       = [];

		// Auto detect rules source
		if ( isSimpleValue( arguments.settings.rules ) ) {
			// Auto detect source
			switch ( arguments.settings.rules ) {
				case "db": {
					arguments.settings.rulesSource = "db";
					break;
				}
				case "model": {
					arguments.settings.rulesSource = "model";
					break;
				}
				default: {
					arguments.settings.rulesFile = arguments.settings.rules;
					if ( findNoCase( "json", arguments.settings.rulesFile ) ) {
						arguments.settings.rulesSource = "json";
					}
					if ( findNoCase( "xml", arguments.settings.rulesFile ) ) {
						arguments.settings.rulesSource = "xml";
					}
				}
			}

			// Reset rules
			arguments.settings.rules = [];
		}

		// Rule Source Checks
		if (
			arguments.settings[ "rulesSource" ].len() && !reFindNoCase(
				"^(xml|db|model|json)$",
				arguments.settings[ "rulesSource" ]
			)
		) {
			throw(
				message = "The rules source you set is invalid: #arguments.settings[ "rulesSource" ]#.",
				detail  = "The valid sources are xml, db, model, or json",
				type    = "Security.InvalidRuleSource"
			);
		}

		switch ( arguments.settings[ "rulesSource" ] ) {
			case "xml":
			case "json": {
				// Check if file property exists
				if ( !arguments.settings[ "rulesFile" ].len() ) {
					throw(
						message = "Please enter a valid rulesFile setting",
						type    = "Security.RulesFileNotDefined"
					);
				}
				break;
			}

			case "db": {
				if ( !arguments.settings[ "rulesDSN" ].len() ) {
					throw(
						message = "Missing setting for DB source: rulesDSN ",
						type    = "Security.RuleDSNNotDefined"
					);
				}
				if ( !arguments.settings[ "rulesTable" ].len() ) {
					throw(
						message = "Missing setting for DB source: rulesTable ",
						type    = "Security.RulesTableNotDefined"
					);
				}
				break;
			}

			case "model": {
				if ( !arguments.settings[ "rulesModel" ].len() ) {
					throw(
						message = "Missing setting for model source: rulesModel ",
						type    = "Security.RulesModelNotDefined"
					);
				}

				break;
			}
		}
		// end of switch statement
	}

	/**
	 * Load rules from an XML file
	 *
	 * @settings The loaded settings
	 */
	function loadXmlRules( required settings ){
		// Validate the XML File
		var node        = "";
		var thisElement = "";

		// Try to locate the file path
		arguments.settings.rulesFile = variables.controller.locateFilePath(
			arguments.settings.rulesFile
		);

		// Validate Location
		if ( !len( arguments.settings.rulesFile ) ) {
			throw(
				message = "Security Rules File could not be located: #arguments.settings.rulesFile#. Please check again.",
				type    = "Security.XMLRulesNotFound"
			);
		}

		// Read in and parse
		return xmlSearch( xmlParse( arguments.settings.rulesFile ), "/rules/rule" ).map( function( node ){
			return parseXmlRule( arguments.node.xmlChildren );
		} );
	}

	/**
	 * Load rules from json file
	 *
	 * @settings The loaded settings
	 */
	array function loadJsonRules( required settings ){
		// Validate the JSON File
		var rulesFile = "";
		var jsonRules = "";
		var x         = 1;
		var thisRule  = "";
		var node      = "";

		// Try to locate the file path
		arguments.settings.rulesFile = variables.controller.locateFilePath(
			arguments.settings.rulesFile
		);

		// Validate Location
		if ( !len( arguments.settings.rulesFile ) ) {
			throw(
				message = "Security Rules File could not be located: #arguments.settings.rulesFile#. Please check again.",
				type    = "Security.RulesFileNotFound"
			);
		}

		// Read in and parse
		var jsonRules = fileRead( arguments.settings.rulesFile );

		// Validate JSON
		if ( !isJSON( jsonRules ) ) {
			throw(
				message = "Security Rules File is not valid JSON: #arguments.settings.rulesFile#. Please check again.",
				type    = "Security.InvalidJson"
			);
		}

		return deserializeJSON( jsonRules ).map( function( item ){
			structAppend( item, getRuleTemplate(), false );
			return item;
		} );
	}

	/**
	 * Load rules from a database
	 *
	 * @settings The loaded settings
	 */
	array function loadDBRules( required settings ){
		var ruleSql = arguments.settings.rulesSQL;

		// Core SQL or they are using their own
		if ( !len( arguments.settings.rulesSQL ) ) {
			ruleSql = "SELECT * FROM #arguments.settings.rulesTable#";
			if ( len( arguments.settings.rulesOrderBy ) ) {
				ruleSql &= " ORDER BY #arguments.settings.rulesOrderBy#";
			}
		}

		return queryToArray(
			queryExecute(
				ruleSql,
				[],
				{ datasource : arguments.settings.rulesDSN }
			)
		);
	}

	/**
	 * Load rules from an IOC bean
	 *
	 * @settings The loaded settings
	 */
	function loadModelRules( required settings ){
		//  Get rules from a Model Object
		var oModel = variables.wirebox.getInstance( arguments.settings.rulesModel );

		// Get the rules
		var rules = invoke( oModel, arguments.settings.rulesModelMethod );

		// Determine type and normalize
		if ( isQuery( rules ) ) {
			return queryToArray( rules );
		} else {
			return rules.map( function( item ){
				structAppend( item, getRuleTemplate(), false );
				return item;
			} );
		}
	}

	/**
	 * Creates a default rule template with all our required fields and defaults
	 */
	struct function getRuleTemplate(){
		return {
			"whitelist"     : "", // A list of white list events or Uri's
			"securelist"    : "", // A list of secured list events or Uri's
			"match"         : "event", // Match the event or a url
			"roles"         : "", // Attach a list of roles to the rule
			"permissions"   : "", // Attach a list of permissions to the rule
			"redirect"      : "", // If rule breaks, and you have a redirect it will redirect here
			"overrideEvent" : "", // If rule breaks, and you have an event, it will override it
			"useSSL"        : false, // Force SSL,
			"action"        : "", // The action to use (redirect|override) when no redirect or overrideEvent is defined in the rule.
			"module"        : "" // metadata we can add so mark rules that come from modules
		};
	}

	/****************************** PRIVATE ********************************/

	/**
	 * Convert the query to an array of rules
	 *
	 * @query The target query to convert
	 */
	private function queryToArray( required query ){
		return arguments.query
			.reduce( function( results, item ){
				arrayAppend( results, item );
				return results;
			}, [] )
			.map( function( item ){
				structAppend( item, getRuleTemplate(), false );
				return item;
			} );
	}

	/**
	 * Parse an XML node into a cbSecurity rule
	 *
	 * @xmlNode The XML node to parse
	 */
	private struct function parseXmlRule( required xmlNode ){
		return arguments.xmlNode.reduce( function( results, item ){
			results[ trim( item.xmlName ) ] = trim( item.xmlText );
			return results;
		}, getRuleTemplate() );
	}

}
