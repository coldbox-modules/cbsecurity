component {

	// Module Properties
	this.title              = "mod1";
	this.author             = "";
	this.webURL             = "";
	this.description        = "";
	this.version            = "1.0.0";
	// If true, looks for views in the parent first, if not found, then in the module. Else vice-versa
	this.viewParentLookup   = true;
	// If true, looks for layouts in the parent first, if not found, then in module. Else vice-versa
	this.layoutParentLookup = true;
	// Module Entry Point
	this.entryPoint         = "mod1";
	// Inherit Entry Point
	this.inheritEntryPoint  = false;
	// Model Namespace
	this.modelNamespace     = "mod1";
	// CF Mapping
	this.cfmapping          = "mod1";
	// Auto-map models
	this.autoMapModels      = true;
	// Module Dependencies
	this.dependencies       = [];

	function configure(){
		// module settings - stored in modules.name.settings
		settings = {
			// CB Security Rules to append to global rules
			cbsecurity : {
				firewall : {
					// Module Relocation when an invalid access is detected, instead of each rule declaring one.
					"invalidAuthenticationEvent" : "mod1:secure.index",
					// Module override event when an invalid access is detected, instead of each rule declaring one.
					"invalidAuthorizationEvent"  : "mod1:secure.auth",
					// You can define your security rules here or externally via a source
					"rules"                      : [
						{
							"secureList" : "mod1/modOverride",
							"match"      : "url",
							"action"     : "override"
						},
						{ "secureList" : "mod1:home" }
					]
				}
			}
		};

		// SES Routes
		routes = [
			// Module Entry Point
			{
				pattern : "/modOverride",
				handler : "home",
				action  : "index"
			},
			{ pattern : "/", handler : "home", action : "index" },
			// Convention Route
			{ pattern : "/:handler/:action?" }
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
