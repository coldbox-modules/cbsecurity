/**
 * Copyright since 2016 by Ortus Solutions, Corp
 * www.ortussolutions.com
 * ---
 * Rule loader service. This object is in charge of loading rules from many different types of sources:
 * - xml
 * - json
 * - array
 * - database
 * - model
 */
component accessors="true" singleton threadsafe {

	// DI
	property name="controller" inject="coldbox";
	property name="wirebox"    inject="wirebox";

	/**
	 * Constructor
	 */
	function init(){
		return this;
	}

	/**
	 * Utility function to normalize an array of rules to our standards
	 *
	 * @rules    The rules to normalize
	 * @module   The module to incorporate if passed
	 * @defaults A set of defaults to incorporate into the rules
	 */
	array function normalizeRules(
		required array rules,
		module   = "",
		defaults = {}
	){
		return arguments.rules.map( function( item ){
			// Append template + defaults
			arguments.item        = getRuleTemplate().append( arguments.item ).append( defaults, false );
			arguments.item.module = module;
			return arguments.item;
		} );
	}

	/**
	 * Load the appropriate rules from the source and return them in consumable focus.
	 *
	 * @provider The firewall rules provider configuration
	 * @defaults Defaults to incorporate to each rule
	 *
	 * @return The loaded rules the source produced
	 */
	array function loadRules( required provider, defaults = {} ){
		// Load Rules
		switch ( arguments.provider.source ) {
			case "xml": {
				return loadXMLRules( arguments.provider, arguments.defaults );
			}
			case "json": {
				return loadJSONRules( arguments.provider, arguments.defaults );
			}
			case "db": {
				return loadDBRules( arguments.provider, arguments.defaults );
			}
			case "model": {
				return loadModelRules( arguments.provider, arguments.defaults );
			}
		}
	}

	/**
	 * Validate from where we are getting rules from. This prepares the settings and normalizes them.
	 *
	 * @provider The firewall rules provider configuration
	 *
	 * @throws Security.InvalidRuleSource     - When the source is invalid
	 * @throws Security.MissingSourceProperty - When a source is missing a required
	 */
	RulesLoader function rulesSourceChecks( required provider ){
		param arguments.provider.source     = "";
		param arguments.provider.properties = {};

		// If there is no provider, skip out, nothing to do, move along!!!
		if ( !len( arguments.provider.source ) ) {
			return this;
		}

		// json | xml file shortcuts
		if ( findNoCase( ".json", arguments.provider.source ) ) {
			arguments.provider.properties.file = arguments.provider.source;
			arguments.provider.source          = "json";
		}
		if ( findNoCase( ".xml", arguments.provider.source ) ) {
			arguments.provider.properties.file = arguments.provider.source;
			arguments.provider.source          = "xml";
		}

		// Rule Source Checks
		if ( !reFindNoCase( "^(xml|db|model|json)$", arguments.provider.source ) ) {
			throw(
				message = "The rules source you set is invalid: #arguments.provider.source#.",
				detail  = "The valid sources are xml, db, model, or json",
				type    = "Security.InvalidRuleSource"
			);
		}

		// Specific Rule Checks
		switch ( arguments.provider.source ) {
			case "xml":
			case "json": {
				// Defaults
				param arguments.provider.properties.file = "";
				// Check if file property exists
				if ( !arguments.provider.properties.file.len() ) {
					throw(
						message = "Please enter a valid file property for the rule source",
						type    = "Security.MissingSourceProperty"
					);
				}
				break;
			}

			case "db": {
				// Defaults
				param arguments.provider.properties.dsn     = "";
				param arguments.provider.properties.table   = "";
				param arguments.provider.properties.orderby = "";
				param arguments.provider.properties.sql     = "select * from #arguments.provider.properties.table#";
				// Verify Properties
				if ( !arguments.provider.properties[ "dsn" ].len() ) {
					throw(
						message = "Missing property for DB source: dsn ",
						type    = "Security.MissingSourceProperty"
					);
				}
				if ( !arguments.provider.properties[ "table" ].len() ) {
					throw(
						message = "Missing property for DB source: table ",
						type    = "Security.MissingSourceProperty"
					);
				}
				break;
			}

			case "model": {
				// Defaults
				param arguments.provider.properties.model  = "";
				param arguments.provider.properties.method = "getSecurityRules";
				if ( !arguments.provider.properties[ "model" ].len() ) {
					throw(
						message = "Missing property for model source: model ",
						type    = "Security.MissingSourceProperty"
					);
				}

				break;
			}
		}
		// end of switch statement

		return this;
	}

	/**
	 * Load rules from an XML file
	 *
	 * @provider The firewall rules provider configuration
	 * @defaults Defaults to incorporate to each rule
	 */
	function loadXmlRules( required provider, defaults = {} ){
		// Validate the XML File
		var node        = "";
		var thisElement = "";

		// Try to locate the file path
		arguments.provider.properties.file = variables.controller.locateFilePath(
			arguments.provider.properties.file
		);

		// Validate Location
		if ( !len( arguments.provider.properties.file ) ) {
			throw(
				message = "Security Rules File could not be located: #arguments.provider.properties.file#. Please check again.",
				type    = "Security.XMLRulesNotFound"
			);
		}

		// Read in and parse
		return xmlSearch( xmlParse( arguments.provider.properties.file ), "/rules/rule" ).map( function( node ){
			return getRuleTemplate().append( parseXmlRule( arguments.node.xmlChildren ) ).append( defaults, false );
		} );
	}

	/**
	 * Load rules from json file
	 *
	 * @provider The firewall rules provider configuration
	 * @defaults Defaults to incorporate to each rule
	 */
	array function loadJsonRules( required provider, defaults = {} ){
		// Validate the JSON File
		var rulesFile = "";
		var jsonRules = "";
		var x         = 1;
		var thisRule  = "";
		var node      = "";

		// Try to locate the file path
		arguments.provider.properties.file = variables.controller.locateFilePath(
			arguments.provider.properties.file
		);

		// Validate Location
		if ( !len( arguments.provider.properties.file ) ) {
			throw(
				message = "Security Rules File could not be located: #arguments.provider.properties.file#. Please check again.",
				type    = "Security.RulesFileNotFound"
			);
		}

		// Read in and parse
		var jsonRules = fileRead( arguments.provider.properties.file );

		// Validate JSON
		if ( !isJSON( jsonRules ) ) {
			throw(
				message = "Security Rules File is not valid JSON: #arguments.provider.properties.file#. Please check again.",
				type    = "Security.InvalidJson"
			);
		}

		return deserializeJSON( jsonRules ).map( function( item ){
			return getRuleTemplate().append( arguments.item ).append( defaults, false );
		} );
	}

	/**
	 * Load rules from a database
	 *
	 * @provider The firewall rules provider configuration
	 * @defaults Defaults to incorporate to each rule
	 */
	array function loadDBRules( required provider, defaults = {} ){
		var ruleSql = arguments.provider.properties.sql;

		if ( len( arguments.provider.properties.orderBy ) ) {
			ruleSql &= " ORDER BY #arguments.provider.properties.orderBy#";
		}

		return queryToArray(
			queryExecute(
				ruleSql,
				[],
				{ datasource : arguments.provider.properties.dsn }
			)
		).map( function( item ){
			return getRuleTemplate().append( arguments.item ).append( defaults, false );
		} );
	}

	/**
	 * Load rules from an IOC bean
	 *
	 * @provider The firewall rules provider configuration
	 * @defaults Defaults to incorporate to each rule
	 */
	function loadModelRules( required provider, defaults = {} ){
		// Get the rules
		var rules = invoke(
			variables.wirebox.getInstance( arguments.provider.properties.model ),
			arguments.provider.properties.method
		);

		// Determine type and normalize
		if ( isQuery( rules ) ) {
			return queryToArray( rules );
		}

		return rules.map( function( item ){
			return getRuleTemplate().append( arguments.item ).append( defaults, false );
		} );
	}

	/**
	 * Creates a default rule template with all our required fields and defaults
	 */
	struct function getRuleTemplate(){
		return {
			"id"            : createUUID(),
			"whiteList"     : "", // A list of white list events or Uri's
			"secureList"    : "", // A list of secured list events or Uri's
			"match"         : "event", // Match the event or a url
			"roles"         : "", // Attach a list of roles to the rule
			"permissions"   : "", // Attach a list of permissions to the rule
			"redirect"      : "", // If rule breaks, and you have a redirect it will redirect here
			"overrideEvent" : "", // If rule breaks, and you have an event, it will override it
			"useSSL"        : false, // Force SSL,
			"action"        : "", // The action to use (redirect|override|block) when no redirect or overrideEvent is defined in the rule.
			"module"        : "", // metadata we can add so mark rules that come from modules
			"httpMethods"   : "*", // Match all HTTP methods or particular ones as a list
			"allowedIPs"    : "*" // The rule only matches if the IP list matches. It can be a list of IPs to match.
		};
	}

	/****************************** PRIVATE ********************************/

	/**
	 * Convert the query to an array of rules
	 *
	 * @query The target query to convert
	 */
	private function queryToArray( required query ){
		return arguments.query.reduce( function( results, item ){
			arrayAppend( results, item );
			return results;
		}, [] );
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
		}, {} );
	}

}
