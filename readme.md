[![Build Status](https://travis-ci.org/coldbox-modules/cbsecurity.svg?branch=development)](https://travis-ci.org/coldbox-modules/cbsecurity)

# WELCOME TO THE COLDBOX SECURITY MODULE

This module will enhance your ColdBox applications by providing out of the box security in the form of:

- A security rule engine for incoming requests
- Annotation driven security for handlers and actions
- JWT (Json Web Tokens) generator, decoder and authentication services
- Refresh and Access tokens
- Pluggable with any Authentication service or can leverage [cbauth](https://github.com/elpete/cbauth) by default
- Capability to distinguish between invalid authentication and invalid authorization and determine an outcome of the process.  
- Ability to load/unload security rules from contributing modules. So you can create a nice HMVC hierarchy of security.
- Ability for each module to define it's own `validator`

Welcome to SecureLand!

## License

Apache License, Version 2.0.

## Links

- https://github.com/coldbox-modules/cbsecurity
- https://forgebox.io/view/cbsecurity
- https://coldbox-security.ortusbooks.com/

## Requirements

- Lucee 5+
- ColdFusion 2016+

## Installation

Use CommandBox to install

`box install cbsecurity`

You can then continue to configure the firewall in your `config/Coldbox.cfc`.

## Settings

Below are the security settings you can use for this module. Remember you must create the `cbsecurity` and `cbauth` structs in your `ColdBox.cfc`:

```js
moduleSettings = {

cbauth = {
	// This is the path to your user object that contains the credential validation methods
	userServiceClass = "entities.user"
},
cbsecurity = {
	// The global invalid authentication event or URI or URL to go if an invalid authentication occurs
	"invalidAuthenticationEvent"	: "",
	// Default Authentication Action: override or redirect when a user has not logged in
	"defaultAuthenticationAction"	: "redirect",
	// The global invalid authorization event or URI or URL to go if an invalid authorization occurs
	"invalidAuthorizationEvent"		: "",
	// Default Authorization Action: override or redirect when a user does not have enough permissions to access something
	"defaultAuthorizationAction"	: "redirect",
	// You can define your security rules here or externally via a source
	"rules"							: [],
	// The validator is an object that will validate rules and annotations and provide feedback on either authentication or authorization issues.
	"validator"						: "CBAuthValidator@cbsecurity",
	// The WireBox ID of the authentication service to use in cbSecurity which must adhere to the cbsecurity.interfaces.IAuthService interface.
	"authenticationService"  		: "authenticationService@cbauth",
	// WireBox ID of the user service to use
	"userService"             		: "",
	// The name of the variable to use to store an authenticated user in prc scope if using a validator that supports it.
	"prcUserVariable"         		: "oCurrentUser",
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
	"useSSL"						: false,
	// Auto load the global security firewall
	"autoLoadFirewall"				: true,
	// Activate handler/action based annotation security
	"handlerAnnotationSecurity"		: true,
	// Activate security rule visualizer, defaults to false by default
	"enableSecurityVisualizer"		: false,
	// JWT Settings
	"jwt"                     		: {
		// The issuer authority for the tokens, placed in the `iss` claim
		"issuer"				  : "",
		// The jwt secret encoding key, defaults to getSystemEnv( "JWT_SECRET", "" )
		"secretKey"               : getSystemSetting( "JWT_SECRET", "" ),
		// by default it uses the authorization bearer header, but you can also pass a custom one as well.
		"customAuthHeader"        : "x-auth-token",
		// The expiration in minutes for the jwt tokens
		"expiration"              : 60,
		// If true, enables refresh tokens, longer lived tokens (not implemented yet)
		"enableRefreshTokens"     : false,
		// The default expiration for refresh tokens, defaults to 30 days
		"refreshExpiration"          : 10080,
		// The Custom header to inspect for refresh tokens
		"customRefreshHeader"        : "x-refresh-token",
		// If enabled, the JWT validator will inspect the request for refresh tokens and expired access tokens
		// It will then automatically refresh them for you and return them back as
		// response headers in the same request according to the customRefreshHeader and customAuthHeader
		"enableAutoRefreshValidator" : false,
		// Enable the POST > /cbsecurity/refreshtoken API endpoint
		"enableRefreshEndpoint"      : true,
		// encryption algorithm to use, valid algorithms are: HS256, HS384, and HS512
		"algorithm"               : "HS512",
		// Which claims neds to be present on the jwt token or `TokenInvalidException` upon verification and decoding
		"requiredClaims"          : [] ,
		// The token storage settings
		"tokenStorage"            : {
			// enable or not, default is true
			"enabled"       : true,
			// A cache key prefix to use when storing the tokens
			"keyPrefix"     : "cbjwt_",
			// The driver to use: db, cachebox or a WireBox ID
			"driver"        : "cachebox",
			// Driver specific properties
			"properties"    : {
				"cacheName" : "default"
			}
		}
	}
};

}
```

## Usage

Using the default configuration, this module will register the `Security` interceptor automatically for you according to the settings shown above and using the interceptor => (`cbsecurity.interceptor.Security`).  

> **Info** You can deactivate this and load as a manual interceptor via the `autoLoadFirewall` setting.

The interceptor will intercept all calls to your application via the `preProcess()` interception point.  Each request will then be validated against any registered security rules and then validated against any handler/action security annotations (if active) via a Security Validator.  Also, if the request is made to a module, each module has the capability to have it's own separate validator apart from the global one.

> **Info** You can deactivate annotation driven security via the `handlerAnnotationSecurity` setting.

### How does validation happen?

How does the interceptor know a user doesn't have access? Well, here is where you register a Validator CFC (`validator` setting) with the interceptor that implements two validation functions: `ruleValidator() and annotationValidator()`.  

> **Info** You can find an interface for these methods in `cbsecurity.interfaces.ISecurityValidator`

The validator's job is to tell back to the firewall if they are allowed access and if they don't, what type of validation they broke: **authentication** or **authorization**.

> `Authentication` is when a user is NOT logged in

> `Authorization` is when a user does not have the right permissions to access an event/handler or action.

## Validation Process

Once the firewall has the results and the user is NOT allowed access. Then the following will occur:

- The request will be logged via LogBox
- The current URL will be flashed as `_securedURL` so it can be used in relocations
- If using a rule, the rule will be stored in `prc` as `cbsecurity_matchedRule`
- The validator results will be stored in `prc` as `cbsecurity_validatorResults`
- If the type of invalidation is `authentication` the `cbSecurity_onInvalidAuthentication` interception will be announced
- If the type of invalidation is `authorization` the `cbSecurity_onInvalidAuthorization` interception will be announced
- If the type is `authentication` the default action for that type will be executed (An override or a relocation) `invalidAuthenticationEvent`
- If the type is `authorization` the default action for that type will be executed (An override or a relocation) `invalidAuthorizationEvent`

### Caveats

If you are securing a module, then the module has the capability to override the global settings if it declares them in its `ModuleConfig.cfc`

## Security Rules

Rules can be declared in your `config/ColdBox.cfc` or in any module's `ModuleConfig.cfc` inline, or they can come from the following sources:

- A json file
- An xml file
- The database by adding the configuration settings for it
- A model by executing the `getSecurityRules()` method from it

### Rule Anatomy

A rule is a struct that can be composed of the following elements.  All of them are optional except the `secureList`.

```js
rules = [
	{
		"whitelist" 	: "", // A list of white list events or Uri's
		"securelist"	: "", // A list of secured list events or Uri's
		"match"			: "event", // Match the event or a url
		"roles"			: "", // Attach a list of roles to the rule
		"permissions"	: "", // Attach a list of permissions to the rule
		"redirect" 		: "", // If rule breaks, and you have a redirect it will redirect here
		"overrideEvent"	: "", // If rule breaks, and you have an event, it will override it
		"useSSL"		: false, // Force SSL,
		"action"		: "", // The action to use (redirect|override) when no redirect or overrideEvent is defined in the rule.
		"module"		: "" // metadata we can add so mark rules that come from modules
	};
]
```

### Global Rules

The global rules come from the `config/Coldbox.cfc` and they are defined within the `cbsecurity` module setting.

```js
// Module Settings
moduleSettings = {
	// CB Security
	cbSecurity : {
		// Global Relocation when an invalid access is detected, instead of each rule declaring one.
		"invalidAuthenticationEvent" 	: "main.index",
		// Global override event when an invalid access is detected, instead of each rule declaring one.
		"invalidAuthorizationEvent"		: "main.index",
		// Default invalid action: override or redirect when an invalid access is detected, default is to redirect
		"defaultAuthorizationAction"	: "redirect",
		// The global security rules
		"rules" 						: [
			// should use direct action and do a global redirect
			{
				"whitelist": "",
				"securelist": "admin",
				"match": "event",
				"roles": "admin",
				"permissions": "",
				"action" : "redirect"
			},
			// no action, use global default action
			{
				"whitelist": "",
				"securelist": "noAction",
				"match": "url",
				"roles": "admin",
				"permissions": ""
			},
			// Using overrideEvent only, so use an explicit override
			{
				"securelist": "ruleActionOverride",
				"match": "url",
				"overrideEvent": "main.login"
			},
			// direct action, use global override
			{
				"whitelist": "",
				"securelist": "override",
				"match": "url",
				"roles": "",
				"permissions": "",
				"action" : "override"
			},
			// Using redirect only, so use an explicit redirect
			{
				"securelist": "ruleActionRedirect",
				"match": "url",
				"redirect": "main.login"
			}
		]
	}
};
```

### Module Rules

Module rules come from the `ModuleConfig.cfc` by creating a `cbSecurity` key in the module's `settings` struct:

```js
// module settings - stored in modules.name.settings
settings = {

	// CB Security Rules to append to global rules
	cbsecurity = {
		// Module Relocation when an invalid access is detected, instead of each rule declaring one.
		"invalidAuthenticationEvent" 	: "mod1:secure.index",
		// Default Auhtentication Action: override or redirect when a user has not logged in
		"defaultAuthenticationAction"	: "override",
		// Module override event when an invalid access is detected, instead of each rule declaring one.
		"invalidAuthorizationEvent"		: "mod1:secure.auth",
		// Default Authorization Action: override or redirect when a user does not have enough permissions to access something
		"defaultAuthorizationAction"	: "override",
		// Custom validator for the module.
		"validator" 					: "jwtService@cbsecurity"
		// You can define your security rules here or externally via a source
		"rules"							: [
			{
				"secureList" 	: "mod1:home"
			},
			{
				"secureList" 	: "mod1/modOverride",
				"match"			: "url",
				"action"		: "override"
			}
		]
	}

};
```

## Annotation Security

The firewall will inspect handlers for the `secured` annotation.  This annotation can be added to the entire handler or to an action or both.  The default value of the `secured` annotation is a boolean `true`.  Which means, we need a user to be authenticated in order to access it.

```js
// Secure this handler
component secured{

	function index(event,rc,prc){}
	function list(event,rc,prc){}

}

// Same as this
component secured=true{
}

// Not the same as this
component secured=false{
}
// Or this
component{

	function index(event,rc,prc) secured{

	}
	
	function list(event,rc,prc) secured="list"{

	}

}
```

### Authorization Context

You can also give the annotation some value, which can be anything you like: A list of roles, a role, a list of permissions, metadata, etc.  Whatever it is, this is the **authorization context** and the security validator must be able to not only authenticate but authorize the context or an invalid authorization will occur.

```js
// Secure this handler
component secured="admin,users"{

	function index(event,rc,prc) secured="list"{

	}
	
	function save(event,rc,prc) secured="write"{

	}

}
```

### Cascading Security

By having the ability to annotate the handler and also the action you create a cascading security model where they need to be able to access the handler first and only then will the action be evaluated for access as well.

## Security Validator

Now that we have seen security rules and also security annotations let's see how to actually validate them.  Create a CFC or use any CFC in your `models` and add the following functions: `ruleValidator() and annotationValidator()`

```js
/**
 * This function is called once an incoming event matches a security rule.
 * You will receive the security rule that matched and an instance of the ColdBox controller.
 *
 * You must return a struct with the following keys:
 * - allow:boolean True, user can continue access, false, invalid access actions will ensue
 * - type:string(authentication|authorization) The type of block that ocurred.  Either an authentication or an authorization issue.
 * - messages:string Any messages for debugging
 *
 * @return { allow:boolean, type:string(authentication|authorization), messages:string }
 */
struct function ruleValidator( required rule, required controller );

/**
 * This function is called once access to a handler/action is detected.
 * You will receive the secured annotation value and an instance of the ColdBox Controller
 *
 * You must return a struct with the following keys:
 * - allow:boolean True, user can continue access, false, invalid access actions will ensue
 * - type:string(authentication|authorization) The type of block that ocurred.  Either an authentication or an authorization issue.
 * - messages:string Any messages for debugging
 *
 * @return { allow:boolean, type:string(authentication|authorization), messages:string }
 */
struct function annotationValidator( required securedValue, required controller );
```

Each validator must return a struct with the following keys:

- `allow:boolean` A boolean indicator if authentication or authorization was violated
- `type:stringOf(authentication|authorization)` A string that indicates the type of violation: authentication or authorization.
- `messages:string` A string of messages used for debugging

Here is a sample validator using permission based security in both rules and annotation context

```js

struct function ruleValidator( required rule, required controller ){
	return permissionValidator( rule.permissions, controller, rule );
}
struct function annotationValidator( required securedValue, required controller ){
	return permissionValidator( securedValue, controller );
}
private function permissionValidator( permissions, controller, rule ){
	var results = { "allow" : false, "type" : "authentication", "messages" : "" };
	var user 	= security.getCurrentUser();

	// First check if user has been authenticated.
	if( user.isLoaded() AND user.isLoggedIn() ){
		// Do we have the right permissions
		if( len( arguments.permissions ) ){
			results.allow 	= user.checkPermission( arguments.permission );
			results.type 	= "authorization";
		} else {
			results.allow = true;
		}
	}

	return results;
}
```

## Interceptions

When invalid access or authorizations occur the interceptor will announce the following events:

- `cbSecurity_onInvalidAuthentication`
- `cbSecurity_onInvalidAuthorization`

You will receive the following data in the `interceptData` struct:

- `ip` : The offending Ip address
- `rule` : The security rule intercepted or empty if annotations
- `settings` : The firewall settings
- `validatorResults` : The validator results
- `annotationType` : The annotation type intercepted, `handler` or `action` or empty if rule driven
- `processActions` : A boolean indicator that defaults to true.  If you change this to false, then the interceptor won't fire the invalid actions.  Usually this means, you manually will do them.

## Security Visualizer

This module also ships with a security visualizer that will document all your security rules and your settings in a nice panel.  In order to activate it you must add the `enableSecurityVisualizer` setting to your config and mark it as `true`.  Once enabled you can navigate to: `/cbsecurity` and you will be presented with the visualizer.

> **Important** The visualizer is disabled by default and if it detects an environment of production, it will disable itself.

<img src="https://raw.githubusercontent.com/coldbox-modules/cbsecurity/development/test-harness/visualizer.png" class="img-responsive">

## Running Tests and Contributing

To run the tests, start one of the servers from the `/test-harness` directory.

You will also need a MySQL database seeded with the `/test-harness/tests/resources/cbsecurity.sql` file.
Docker makes this a cinch:

```sh
docker run -d \
  --name=cbsecurity \
  -p 3306:3306 \
  -e MYSQL_ROOT_PASSWORD=mysql \
  -e MYSQL_DATABASE=cbsecurity \
  -v $(pwd)/test-harness/tests/resources/cbsecurity.sql:/docker-entrypoint-initdb.d/cbsecurity.sql \
  mysql:5
```

Finally, run the tests by visiting the `/tests/runner.cfm` file on your server.
********************************************************************************
Copyright Since 2005 ColdBox Framework by Luis Majano and Ortus Solutions, Corp
www.coldbox.org | www.luismajano.com | www.ortussolutions.com
********************************************************************************

### HONOR GOES TO GOD ABOVE ALL

Because of His grace, this project exists. If you don't like this, then don't read it, its not for you.

>"Therefore being justified by faith, we have peace with God through our Lord Jesus Christ:
By whom also we have access by faith into this grace wherein we stand, and rejoice in hope of the glory of God.
And not only so, but we glory in tribulations also: knowing that tribulation worketh patience;
And patience, experience; and experience, hope:
And hope maketh not ashamed; because the love of God is shed abroad in our hearts by the 
Holy Ghost which is given unto us. ." Romans 5:5

### THE DAILY BREAD

 > "I am the way, and the truth, and the life; no one comes to the Father, but by me (JESUS)" Jn 14:1-12
