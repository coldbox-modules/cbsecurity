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

	/**
	 * Module Config
	 */
	function configure(){

		settings = {

		};

	}

	/**
	 * Fired when the module is registered and activated.
	 */
	function onLoad(){
		// Verify we have settings, else ignore loading automatically
		if( structCount( settings ) ){
			controller.getInterceptorService()
				.registerInterceptor(
					interceptorClass		= "cbsecurity.interceptors.Security",
					interceptorProperties	= settings,
					interceptorName			= "CBSecurity"
				);
		}
	}

	/**
	 * Fired when the module is unregistered and unloaded
	 */
	function onUnload(){
	}

}
