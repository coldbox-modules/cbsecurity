/**
 * Copyright since 2016 by Ortus Solutions, Corp
 * www.ortussolutions.com
 * ---
 * Rule loader service
 */
component accessors="true" singleton{

	// DI
	property name="controller" 	inject="coldbox";
	property name="wirebox" 	inject="wirebox";

	/**
	 * Constructor
	 */
	function init(){
		return this;
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
	 * Load rules from an XML file
	 *
	 * @settings The loaded settings
	 */
	function loadXmlRules( required settings ){
		// Validate the XML File
		var node = "";
		var thisElement = "";

		// Try to locate the file path
		arguments.settings.rulesFile = variables.controller.locateFilePath( arguments.settings.rulesFile );

		// Validate Location
		if ( !len( arguments.settings.rulesFile ) ) {
			throw(
				message 	= "Security Rules File could not be located: #arguments.settings.rulesFile#. Please check again.",
				type 		= "Security.XMLRulesNotFound"
			);
		}

		// Read in and parse
		return xmlSearch(
				xmlParse( arguments.settings.rulesFile ),
				"/rules/rule"
			).map( function( node ){
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
		var x = 1;
		var thisRule = "";
		var node = "";

		// Try to locate the file path
		arguments.settings.rulesFile = variables.controller.locateFilePath( arguments.settings.rulesFile );

		// Validate Location
		if ( !len( arguments.settings.rulesFile ) ) {
			throw(
				message = "Security Rules File could not be located: #arguments.settings.rulesFile#. Please check again.",
				type 	= "Security.RulesFileNotFound"
			);
		}

		// Read in and parse
		var jsonRules = fileRead( arguments.settings.rulesFile );

		// Validate JSON
		if ( !isJSON( jsonRules ) ) {
			throw(
				message = "Security Rules File is not valid JSON: #arguments.settings.rulesFile#. Please check again.",
				type 	= "Security.InvalidJson"
			);
		}

		return deserializeJSON( jsonRules )
			.map( function( item ){
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
		if( !len( arguments.settings.rulesSQL ) ){
			ruleSql = "SELECT * FROM #arguments.settings.rulesTable#";
			if( len( arguments.settings.rulesOrderBy ) ){
				ruleSql &= " ORDER BY #arguments.settings.rulesOrderBy#";
			}
		}

		return queryToArray(
			queryExecute(
				ruleSql,
				[],
				{
					datasource : arguments.settings.rulesDSN
				}
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
		var rules = invoke( oModel,	arguments.settings.rulesModelMethod );

		// Determine type and normalize
		if( isQuery( rules ) ){
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
			"whitelist" 	: "", // A list of white list events or Uri's
			"securelist"	: "", // A list of secured list events or Uri's
			"match"			: "event", // Match the event or a url
			"roles"			: "", // Attach a list of roles to the rule
			"permissions"	: "", // Attach a list of permissions to the rule
			"redirect" 		: "", // If rule breaks, and you have a redirect it will redirect here
			"overrideEvent"	: "", // If rule breaks, and you have an event, it will override it
			"useSSL"		: false // Force SSL
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
		return arguments.xmlNode
			.reduce( function( results, item ){
				results[ trim( item.xmlName ) ] = trim( item.xmlText );
				return results;
			}, getRuleTemplate() );
	}

}