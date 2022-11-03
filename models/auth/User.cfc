/**
 * This is a basic user object that can be used with CBSecurity.
 *
 * It implements the following interfaces
 * - cbsecurity.interfaces.jwt.IJwtSubject
 * - cbsecurity.interfaces.IAuthUser
 */
component accessors="true" {

	property name="id";
	property name="firstName";
	property name="lastName";
	property name="username";
	property name="password";
	property name="permissions";
	property name="roles";

	/**
	 * Validation constraints
	 * https://coldbox-validation.ortusbooks.com/overview/valid-constraints
	 */
	this.constraints = {
		firstName : { required : true, size : "1..255" },
		lastName : { required : true, size : "1..255" },
		username : { required : true, size : "1..255" },
		password : { required : true, size : "1..255" }
	};

	/**
	 * Validation profiles
	 * https://coldbox-validation.ortusbooks.com/overview/validating-constraints/validating-with-profiles
	 */
	this.constraintProfiles = {
		"update" : "firstName,lastName,username"
	};

	/**
	 * Mementifier serialization
	 * https://forgebox.io/view/mementifier
	 */
	this.memento = {
		// Default properties to serialize
		defaultIncludes : [
			"firstName",
			"lastName",
			"username",
			"permissions",
			"roles"
		],
		// Default Exclusions
		defaultExcludes : [
		],
		// Never Include
		neverInclude : [ "password" ]
	};

	/**
	 * Constructor
	 */
	function init(){
		variables.id        = "";
		variables.firstName = "";
		variables.lastName  = "";
		variables.username  = "";
		variables.password  = "";
		variables.permissions = [];
		variables.roles       = [];

		return this;
	}

	/**
	 * Set roles into the object
	 *
	 * @roles array or list of roles
	 */
	User function setRoles( roles ){
		if ( isSimpleValue( arguments.roles ) ) {
			arguments.roles = listToArray( arguments.roles );
		}
		variables.roles = arguments.roles;
		return this;
	}

	/**
	 * Set permissions into this object
	 *
	 * @permissions array or list of permissions
	 */
	User function setPermissions( permissions ){
		if ( isSimpleValue( arguments.permissions ) ) {
			arguments.permissions = listToArray( arguments.permissions );
		}
		variables.permissions = arguments.permissions;
		return this;
	}

	/**
	 * Verify if this is a valid user or not
	 */
	boolean function isLoaded(){
		return ( !isNull( variables.id ) && len( variables.id ) );
	}

	/**
	 * A struct of custom claims to add to the JWT token
	 */
	struct function getJWTCustomClaims( required struct payload ){
		return { "role" : variables.roles.toList() };
	}

	/**
	 * This function returns an array of all the scopes that should be attached to the JWT token that will be used for authorization.
	 */
	array function getJWTScopes(){
		return variables.permissions;
	}

	/**
	 * Verify if the user has one or more of the passed in permissions
	 *
	 * @permission One or a list of permissions to check for access
	 */
	boolean function hasPermission( required permission ){
		if ( isSimpleValue( arguments.permission ) ) {
			arguments.permission = listToArray( arguments.permission );
		}

		return arguments.permission
			.filter( function( item ){
				return ( variables.permissions.findNoCase( item ) );
			} )
			.len();
	}

	/**
	 * Verify if the user has one or more of the passed in roles
	 *
	 * @role One or a list of roles to check for access
	 */
	boolean function hasRole( required role ){
		if ( isSimpleValue( arguments.role ) ) {
			arguments.role = listToArray( arguments.role );
		}

		return arguments.role
			.filter( function( item ){
				return ( variables.roles.findNoCase( item ) );
			} )
			.len();
	}

}
