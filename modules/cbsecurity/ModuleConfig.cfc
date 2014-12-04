component {

	// Module Properties
	this.title 				= "cbsecurity";
	this.author 			= "Luis Majano";
	this.webURL 			= "http://www.ortussolutions.com";
	this.description 		= "This module provides a security rule engine for ColdBox Apps";
	this.version			= "1.0.1+@build.number@";
	// If true, looks for views in the parent first, if not found, then in the module. Else vice-versa
	this.viewParentLookup 	= true;
	// If true, looks for layouts in the parent first, if not found, then in module. Else vice-versa
	this.layoutParentLookup = true;
	// Module Entry Point
	this.entryPoint			= "cbsecurity";
	// Model Namespace
	this.modelNamespace		= "cbsecurity";
	// CF Mapping
	this.cfmapping			= "cbsecurity";

	function configure(){

		// Security Interceptor declaration.
		interceptors = [
			{ class="cbsecurity.interceptors.Security",
			  name="CBSecurity",
			  properties={
			  	// please add the properties you want here to configure the security interceptor
			  	rulesFile = "/cbsecurity/config/security.json.cfm",
			  	rulesSource = "json"
			 } }
		];

	}

	/**
	* Fired when the module is registered and activated.
	*/
	function onLoad(){

	}

	/**
	* Fired when the module is unregistered and unloaded
	*/
	function onUnload(){

	}

}