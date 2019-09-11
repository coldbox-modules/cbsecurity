/**
 * Copyright Since 2005 ColdBox Framework by Luis Majano and Ortus Solutions, Corp
 * ---
 * Module Configuration
 */
component {

	// Module Properties
	this.title 				= "cbsecurity";
	this.author 			= "Ortus Solutions, Corp";
	this.webURL 			= "https://www.ortussolutions.com";
	this.description 		= "This module provides robust security for ColdBox Apps";
	// Model Namespace
	this.modelNamespace		= "cbsecurity";
	// CF Mapping
	this.cfmapping			= "cbsecurity";

	// The map of modules contributing security rules
	variables.securedModules = {};

	/**
	 * Module Config
	 */
	function configure(){

		settings = {
			// Global Relocation when an invalid access is detected, instead of each rule declaring one.
			"invalidAccessRedirect" 		: "",
			// Global override event when an invalid access is detected, instead of each rule declaring one.
			"invalidAccessOverrideEvent"	: "",
			// Default invalid action: override or redirect when an invalid access is detected, default is to redirect
			"defaultInvalidAction"			: "redirect",
			// You can define your security rules here or externally via a source
			"rules"							: [],
			// Where are the rules, valid options: json,xml,db,model
			"rulesSource" 					: "",
			// The location of the rules file, applies to json|xml ruleSource
			"rulesFile"						: "",
			// The rule validator model, this must have a method like this `userValidator( rule, controller )			:boolean`
			// By default we use the CFSecurity validator
			"validator"						: "CFValidator@cbsecurity",
			// If source is model, the wirebox Id to use for retrieving the rules
			"rulesModel"					: "",
			// If source is model, then the name of the method to get the rules, we default to `getSecurityRules`
			"rulesModelMethod"				: "getSecurityRules",
			// If source is db then the datasource name to use
			"rulesDSN"						: "",
			// If source is db then the table to get the rules from
			"rulesTable"					: "",
			// If source is db then the ordering of the select
			"rulesOrderBy"					: "",
			// If source is db then you can have your custom select SQL
			"rulesSql" 						: "",
			// Use regular expression matching on the rule match types
			"useRegex" 						: true,
			// Force SSL for all relocations
			"useSSL"						: false
		};

		interceptorSettings = {
			customInterceptionPoints = [
				"cbSecurity_onInvalidAccess" // Fires when a security rule matches and the user validator reports an invalid access
			]
		};

	}

	/**
	 * Fired when the module is registered and activated.
	 */
	function onLoad(){
		// Check the global settings for rules or a rules source
		if( len( settings.rulesSource ) || arrayLen( settings.rules ) ){
			controller.getInterceptorService()
				.registerInterceptor(
					interceptorClass		= "cbsecurity.interceptors.Security",
					interceptorProperties	= settings,
					interceptorName			= "cbsecurity@global"
				);
		}
	}

	/**
	 * Fired when the module is unregistered and unloaded
	 */
	function onUnload(){
	}

	/**
	 * Listen when modules are activated to load their cbSecurity capabilities
	 */
	function afterAspectsLoad( event, interceptData ){
		var modules 			= controller.getSetting( "modules" );
		var moduleService 		= controller.getModuleService();
		var moduleConfigCache 	= moduleService.getModuleConfigCache();

		for( var thisModule in modules ){
			// get module config object
			//var oConfig = moduleConfigCache[ thisModule ];
			// Get i18n Settings
			//var i18nSettings = oConfig.getPropertyMixin( "i18n", "variables", {} );
		}

	}

}
