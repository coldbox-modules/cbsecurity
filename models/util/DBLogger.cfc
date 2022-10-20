/**
 * Copyright since 2016 by Ortus Solutions, Corp
 * www.ortussolutions.com
 * ---
 * This is the logger for firewall actions for cbsecurity. It relies on the `firewall.logs` properties
 *
 * Properties
 * - table : the table to use
 * - schema : the schema to use (if db support it)
 * - dsn : the dsn to use, no dsn, we use the global one
 * - autoCreate : if true, then we will create the table. Defaults to true
 *
 * The columns created in the table are
 *
 * - id : db identifier
 * - logDate : (created date)
 * - action : The action the firewall took: redirect, override, block
 * - blockType : The type of event: authentication, authorization
 * - ip : ip address
 * - host : The host used in the event
 * - userAgent : user agent used
 * - userId : If a logged in user was used, their id
 * - rule : The rule in json that triggered the event
 * - incomingUrl : The incoming Url
 * - httpMethod : The incoming HTTP Method
 *
 */
component accessors="true" singleton threadsafe {

	// DI
	property name="settings" inject="coldbox:moduleSettings:cbSecurity";

	// Columns Used
	variables.COLUMNS = [
		"id",
		"logDate",
		"action",
		"blockType",
		"ip",
		"host",
		"userAgent",
		"userId",
		"rule",
		"incomingUrl",
		"httpMethod"
	];

	/**
	 * Constructor
	 */
	function init(){
		// UUID generator
		variables.uuid = createObject( "java", "java.util.UUID" );
		return this;
	}

	/**
	 * Configure the db logger for operation
	 */
	function configure(){
		// Log settings check
		if ( !len( variables.settings.firewall.logs.table ) ) {
			throw(
				message = "No 'table' property defined for the firewall logs: firewall.logs.table",
				type    = "PropertyNotDefined"
			);
		}
		if ( !len( variables.settings.firewall.logs.autoCreate ) ) {
			variables.settings.firewall.logs.autoCreate = true;
		}
		if ( !len( variables.settings.firewall.logs.dsn ) ) {
			variables.settings.firewall.logs.dsn = getDefaultDatasource();
		}
		if ( !len( variables.settings.firewall.logs.schema ) ) {
			variables.settings.firewall.logs.schema = "";
		}

		// Auto create table
		if ( variables.settings.firewall.logs.autoCreate ) {
			ensureTable();
		}

		return this;
	}

	/**
	 * Is logging enabled or not
	 */
	boolean function canLog(){
		return variables.settings.firewall.logs.enabled;
	}

	/**
	 * Log a firewall event
	 *
	 * @action      The action the firewall took: redirect, override, block
	 * @blockType   The type of event: AUTHENTICATION, AUTHORIZATION, INVALID-HOST, INVALID-IP, NON-SSL
	 * @ip          ip address
	 * @host        The host used in the event
	 * @userAgent   user agent used
	 * @userId      If a logged in user was used, their id
	 * @rule        The rule in json that triggered the event
	 * @incomingUrl The incoming URL
	 * @httpMethod  The incoming HTTP method
	 *
	 * @return DBLogger
	 */
	any function log(
		required action,
		blockType   = "AUTHENTICATION",
		ip          = "127.0.0.1",
		host        = cgi.HTTP_HOST,
		userAgent   = cgi.HTTP_USER_AGENT,
		userId      = "",
		rule        = {},
		incomingUrl = "",
		httpMethod  = CGI.REQUEST_METHOD
	){
		// Don't log if not enabled
		if ( !canLog() ) {
			return this;
		}

		queryExecute(
			"INSERT INTO #getTable()# (#variables.COLUMNS.toList()#)
				VALUES (
					:uuid,
					:logDate,
					:action,
					:blockType,
					:ip,
					:host,
					:userAgent,
					:userId,
					:rule,
					:incomingUrl,
					:httpMethod
				)
			",
			{
				uuid : {
					cfsqltype : "varchar",
					value     : "#variables.uuid.randomUUID().toString()#"
				},
				logDate   : { cfsqltype : "timestamp", value : now() },
				action    : { cfsqltype : "varchar", value : arguments.action },
				blockType : { cfsqltype : "varchar", value : arguments.blockType },
				ip        : { cfsqltype : "varchar", value : arguments.ip },
				host      : { cfsqltype : "varchar", value : arguments.host },
				userAgent : { cfsqltype : "varchar", value : arguments.userAgent },
				userId    : { cfsqltype : "varchar", value : arguments.userId },
				rule      : {
					cfsqltype : "longvarchar",
					value     : serializeJSON( arguments.rule )
				},
				incomingUrl : { cfsqltype : "varchar", value : arguments.incomingUrl },
				httpMethod  : { cfsqltype : "varchar", value : arguments.httpMethod }
			},
			{ datasource : variables.settings.firewall.logs.dsn }
		);

		return this;
	}

	array function getActionsReport(){
		return queryExecute(
			"select count( id ), action from cbsecurity_logs group by action",
			{},
			{ datasource : variables.settings.firewall.logs.dsn }
		).reduce( ( results, row ) => {
			results.append( row );
			return results;
		}, [] );
	}

	/**
	 * Get the top x logs from the table
	 *
	 * @top       How many logs to get, defaults to 100
	 * @action    If passed, we will filter by this action
	 * @blockType If passed, we will filter by this block type
	 * @userId    If passed, we will filter by this user id
	 */
	query function getLatest(
		numeric top = 100,
		action      = "",
		blockType   = "",
		userId      = ""
	){
		var sql   = "";
		var where = "WHERE 1=1";

		if ( len( arguments.action ) ) {
			where &= " AND action = :action";
		}
		if ( len( arguments.blockType ) ) {
			where &= " AND blockType = :blockType";
		}
		if ( len( arguments.userId ) ) {
			where &= " AND userId = :userId";
		}

		switch ( getDatabaseVendor() ) {
			case "MySQL":
			case "PostgreSQL": {
				sql = "SELECT * FROM #getTable()# #where# ORDER BY logDate desc LIMIT :top";
				break;
			}
			case "Microsoft SQL Server": {
				sql = "SELECT TOP :top * FROM #getTable()# #where# ORDER BY logDate desc";
				break;
			}
			case "Oracle": {
				sql = "SELECT * FROM #getTable()# #where# ORDER BY logDate desc FETCH FIRST :top ROWS ONLY";
				break;
			}
		}
		return queryExecute(
			sql,
			{
				top       : { cfsqltype : "integer", value : arguments.top },
				action    : arguments.action,
				blockType : arguments.blockType,
				userId    : arguments.userId
			},
			{ datasource : variables.settings.firewall.logs.dsn }
		);
	}

	/**
	 * Clear all the logs by truncating the table
	 *
	 * @return DBLogger
	 */
	any function clearAll(){
		queryExecute(
			"TRUNCATE TABLE #getTable()#",
			{},
			{ datasource : variables.settings.firewall.logs.dsn }
		);

		return this;
	}

	/**
	 * How many logs do we have
	 */
	numeric function count(){
		var q = queryExecute(
			"SELECT count( id ) as totalCount
			   FROM #getTable()#
			",
			{},
			{ datasource : variables.settings.firewall.logs.dsn }
		);

		return q.totalCount;
	}

	/******************************** PRIVATE ************************************/

	/**
	 * Get the default application datasource
	 */
	private string function getDefaultDatasource(){
		// get application metadata
		var settings = getApplicationMetadata();

		// check orm settings first
		if ( structKeyExists( settings, "ormsettings" ) AND structKeyExists( settings.ormsettings, "datasource" ) ) {
			return settings.ormsettings.datasource;
		}

		// else default to app datasource
		if ( !isNull( settings.datasource ) ) {
			return settings.datasource;
		}

		throw( message = "No default datasource defined and no dsn property found", type = "PropertyNotDefined" );
	}

	/**
	 * Return the table name with the appropriate schema included if found.
	 */
	private function getTable(){
		if ( len( variables.settings.firewall.logs.schema ) ) {
			return variables.settings.firewall.logs.schema & "." & variables.settings.firewall.logs.table;
		}
		return variables.settings.firewall.logs.table;
	}

	/**
	 * Verify or create the logging table
	 */
	private function ensureTable(){
		var tableFound = false;
		var qCreate    = "";

		// Get Tables on this DSN
		cfdbinfo(
			datasource = "#variables.settings.firewall.logs.dsn#",
			name       = "local.qTables",
			type       = "tables"
		);
		// Find the table
		for ( var thisRecord in local.qTables ) {
			if ( thisRecord.table_name == variables.settings.firewall.logs.table ) {
				tableFound = true;
				break;
			}
		}

		// create it
		if ( NOT tableFound ) {
			transaction {
				queryExecute(
					"CREATE TABLE #getTable()# (
						id VARCHAR(36) NOT NULL,
						logDate #getDateTimeColumnType()# NOT NULL,
						action VARCHAR(20) NOT NULL,
						blockType VARCHAR(20) NOT NULL,
						ip VARCHAR(100) NOT NULL,
						host VARCHAR(255) NOT NULL,
						userAgent VARCHAR(255) NOT NULL,
						userId VARCHAR(36),
						rule #getTextColumnType()#,
						incomingUrl VARCHAR(255) NOT NULL,
						httpMethod VARCHAR(25) NOT NULL,
						PRIMARY KEY (id)
					)",
					{},
					{ datasource : variables.settings.firewall.logs.dsn }
				);

				queryExecute(
					"CREATE INDEX idx_cbsecurity ON #getTable()# (logDate,action,blockType,incomingUrl)",
					{},
					{ datasource : variables.settings.firewall.logs.dsn }
				);

				queryExecute(
					"CREATE INDEX idx_cbsecurity_userId ON #getTable()# (userId)",
					{},
					{ datasource : variables.settings.firewall.logs.dsn }
				);
			}
		}
	}

	/**
	 * Get db specific text column type
	 */
	private function getTextColumnType(){
		switch ( getDatabaseVendor() ) {
			case "PostgreSQL": {
				return "TEXT";
			}
			case "MySQL": {
				return "LONGTEXT";
			}
			case "Microsoft SQL Server": {
				return "TEXT";
			}
			case "Oracle": {
				return "LONGTEXT";
			}
			default: {
				return "TEXT";
			}
		}
	}

	/**
	 * Get db specific text column type
	 */
	private function getDateTimeColumnType(){
		switch ( getDatabaseVendor() ) {
			case "PostgreSQL": {
				return "TIMESTAMP";
			}
			case "MySQL": {
				return "DATETIME";
			}
			case "Microsoft SQL Server": {
				return "DATETIME";
			}
			case "Oracle": {
				return "DATE";
			}
			default: {
				return "DATETIME";
			}
		}
	}

	/**
	 * Get the specifc db we are on
	 */
	private function getDatabaseVendor(){
		var qResults = "";

		cfdbinfo(
			type       = "Version",
			name       = "qResults",
			datasource = "#variables.settings.firewall.logs.dsn#"
		);

		return qResults.database_productName;
	}

}
