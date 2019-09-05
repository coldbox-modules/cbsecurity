<cfcomponent output="false" cache="true" cachetimeout="5" cacheLastAccessTimeout="1">
	<!--- Some Autowire stuff --->
	<cfproperty name="myMailSettings" type="ioc">
	<cfproperty name="myDatasource" type="ioc" scope="instance">
	<cfproperty name="loggerPlugin" type="ioc" scope="this">

	<!--- Setter INjection Test. --->
	<cffunction name="setMyDatasource" access="public" output="false" returntype="void" hint="Set MyDatasource">
		<cfargument name="MyDatasource" type="any" required="true"/>
		<cfset variables.setterInjection.MyDatasource = arguments.MyDatasource/>
	</cffunction>

	<cffunction name="init" access="public" returntype="security" hint="" output="false">
		<cfscript>
		return this;
		</cfscript>
	</cffunction>

	<cffunction name="getRules" access="public" returntype="query" hint="" output="false">
		<cfscript>
		var qRules = queryNew( "rule_id,securelist,whitelist,roles,permissions,redirect" );

		queryAddRow( qRules, 1 );
		querySetCell( qrules, "rule_id", createUUID() );
		querySetCell( qrules, "securelist", "^user\..*, ^admin" );
		querySetCell( qrules, "whitelist", "user.login,user.logout,^main.*" );
		querySetCell( qrules, "roles", "admin" );
		querySetCell( qrules, "permissions", "WRITE" );
		querySetCell( qrules, "redirect", "user.login" );

		return qRules;
		</cfscript>
	</cffunction>

	<cffunction name="userValidator" access="public" returntype="boolean" hint="Validate a user" output="false">
		<cfargument name="rule" required="true" type="struct" hint="">
		<cfreturn true>
	</cffunction>
</cfcomponent>
