/**
 * Copyright since 2016 by Ortus Solutions, Corp
 * www.ortussolutions.com
 * ---
 * Route middleware that secures a ColdBox route using the same validators, invalid actions
 * (redirect, override or block), interception points and logging as the cbsecurity firewall.
 *
 * It requires the firewall interceptor (`firewall.autoLoadFirewall`, enabled by default).
 *
 * Use one of the ready made middleware:
 * - `Authenticated@cbsecurity`: the user must be logged in
 * - `Authorized@cbsecurity`: the user must be logged in and satisfy the route's permissions or roles
 * - `JwtAuth@cbsecurity`: like `Authorized` but authenticating with a JWT
 * - `BasicAuth@cbsecurity`: like `Authorized` but authenticating with HTTP Basic credentials
 *
 * Authorization is declared in the route metadata:
 *
 * <pre>
 * route( "/admin" )
 *     .middleware( "Authorized@cbsecurity" )
 *     .meta( { permissions : "ADMIN,EDITOR" } )
 *     .to( "admin.index" )
 * </pre>
 *
 * Supported route metadata keys:
 * - `permissions`: one, a list or an array of permissions
 * - `roles`: one, a list or an array of roles
 * - `mode`: how the permissions are verified: any (default), all or none
 */
component {

	// DI
	property name="wirebox"    inject="wirebox";
	property name="cbSecurity" inject="CBSecurity@cbsecurity";

	// Validator aliases
	variables.VALIDATOR_ALIASES = {
		"auth"   : "AuthValidator@cbsecurity",
		"cbauth" : "CBAuthValidator@cbsecurity",
		"jwt"    : "JwtAuthValidator@cbsecurity",
		"basic"  : "BasicAuthValidator@cbsecurity"
	};

	// The WireBox ID of the firewall interceptor
	variables.FIREWALL_ID = "interceptor-cbsecurity@global";

	/**
	 * Constructor
	 *
	 * @permissions Default permissions: one, a list or an array. The route metadata overrides them.
	 * @roles       Default roles: one, a list or an array. Any one role satisfies the check. The route metadata overrides them.
	 * @mode        Default permissions mode: any (one is enough), all (every one is required) or none (the user must not have any of them). The route metadata overrides it.
	 * @validator   An alias (auth, cbauth, jwt, basic) or WireBox ID of the validator to use. Defaults to the firewall's validator.
	 * @useMeta     Read permissions, roles and mode from the route metadata. If false, only the constructor values apply.
	 */
	function init(
		any permissions  = "",
		any roles        = "",
		string mode      = "any",
		string validator = "",
		boolean useMeta  = true
	){
		variables.permissions = toList( arguments.permissions );
		variables.roles       = toList( arguments.roles );
		variables.mode        = validateMode( arguments.mode );
		variables.validator   = variables.VALIDATOR_ALIASES.keyExists( arguments.validator ) ? variables.VALIDATOR_ALIASES[
			arguments.validator
		] : arguments.validator;
		variables.useMeta = arguments.useMeta;

		return this;
	}

	/**
	 * ColdBox route middleware point. Verifies access and, if it fails, processes the firewall's invalid
	 * actions for the failure type (authentication or authorization).
	 *
	 * @event The request context
	 * @rc    The request collection
	 * @prc   The private request collection
	 *
	 * @return True if access was denied, so the remaining middleware of the route is skipped
	 */
	boolean function preProcess( required event, rc, prc ){
		var firewall    = getFirewall();
		var routeMeta   = variables.useMeta ? arguments.event.getPrivateValue( "currentRouteMeta", {} ) : {};
		var permissions = routeMeta.keyExists( "permissions" ) ? toList( routeMeta.permissions ) : variables.permissions;
		var roles       = routeMeta.keyExists( "roles" ) ? toList( routeMeta.roles ) : variables.roles;
		var mode        = routeMeta.keyExists( "mode" ) ? validateMode( routeMeta.mode ) : variables.mode;

		// Validators treat permissions as "any". For "all" and "none", the validator only authenticates
		// and we verify the permissions ourselves once we know who the user is.
		var inlineCheck = mode == "any";
		var results     = firewall.validateAccess(
			event      : arguments.event,
			permissions: inlineCheck ? permissions : "",
			roles      : roles,
			validator  : variables.validator
		);

		if ( results.allow && !inlineCheck && listLen( permissions ) ) {
			var passed = (
				mode == "all" ? variables.cbSecurity.all( permissions ) : variables.cbSecurity.none( permissions )
			);
			if ( !passed ) {
				results.allow    = false;
				results.type     = "authorization";
				results.messages = "The user does not satisfy the [#mode#] permissions check";
			}
		}

		// Denied: same flow as a firewall rule or secured annotation
		if ( !results.allow ) {
			arguments.event.setPrivateValue( "cbSecurity_validatorResults", results );
			firewall.processInvalidAccess( arguments.event, results, "middleware" );
			return true;
		}

		// Allowed: store the user in the prc like the firewall does, it may have authenticated in this request
		try {
			arguments.event.setPrivateValue(
				firewall.getProperty( "authentication" ).prcUserVariable,
				variables.cbSecurity.getUser()
			);
		} catch ( "NoUserLoggedIn" e ) {
			// Nothing to store
		}

		return false;
	}

	/**
	 * Get the firewall interceptor or throw a helpful exception
	 */
	private function getFirewall(){
		if ( !variables.wirebox.containsInstance( variables.FIREWALL_ID ) ) {
			throw(
				type    = "cbsecurity.MiddlewareRequiresFirewall",
				message = "cbsecurity middleware requires the firewall interceptor to be registered. Make sure the `firewall.autoLoadFirewall` setting is true."
			);
		}
		return variables.wirebox.getInstance( variables.FIREWALL_ID );
	}

	/**
	 * Normalize a list or array into a list
	 */
	private string function toList( required any value ){
		return isArray( arguments.value ) ? arrayToList( arguments.value ) : arguments.value;
	}

	/**
	 * Validate a permissions mode
	 *
	 * @mode The mode to validate
	 *
	 * @return The same mode if valid
	 */
	private string function validateMode( required string mode ){
		if ( !listFindNoCase( "any,all,none", arguments.mode ) ) {
			throw(
				type    = "cbsecurity.InvalidMiddlewareMode",
				message = "The mode [#arguments.mode#] is invalid. Valid modes are: any, all, none"
			);
		}
		return lCase( arguments.mode );
	}

}
