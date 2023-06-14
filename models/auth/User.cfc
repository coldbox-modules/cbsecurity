/**
 * Copyright since 2016 by Ortus Solutions, Corp
 * www.ortussolutions.com
 * ---
 * This is a basic user object that can be used with CBSecurity.
 *
 * It implements the following interfaces via it's delegates
 * - cbsecurity.interfaces.jwt.IJwtSubject
 * - cbsecurity.interfaces.IAuthUser
 */
component
	accessors     ="true"
	transientCache="false"
	delegates     ="
		Auth@cbSecurity,
		Authorizable@cbSecurity,
		JwtSubject@cbSecurity
	"
{

	/**
	 * --------------------------------------------------------------------------
	 * Properties
	 * --------------------------------------------------------------------------
	 */
	property name="id";
	property name="firstName";
	property name="lastName";
	property name="username";
	property name="password";
	property name="permissions";
	property name="roles";

	/**
	 * --------------------------------------------------------------------------
	 * Validation constraints
	 * --------------------------------------------------------------------------
	 * https://coldbox-validation.ortusbooks.com/overview/valid-constraints
	 */
	this.constraints = {
		firstName : { required : true, size : "1..255" },
		lastName  : { required : true, size : "1..255" },
		username  : { required : true, size : "1..255" },
		password  : { required : true, size : "1..255" }
	};

	/**
	 * --------------------------------------------------------------------------
	 * Validation profiles
	 * --------------------------------------------------------------------------
	 * https://coldbox-validation.ortusbooks.com/overview/validating-constraints/validating-with-profiles
	 */
	this.constraintProfiles = { "update" : "firstName,lastName,username" };

	/**
	 * --------------------------------------------------------------------------
	 * Mementifier Serialization
	 * --------------------------------------------------------------------------
	 * https://forgebox.io/view/mementifier
	 */
	this.memento = {
		// Default properties to serialize
		defaultIncludes : [
			"id",
			"firstName",
			"lastName",
			"username",
			"permissions",
			"roles"
		],
		// Default Exclusions
		defaultExcludes : [],
		// Never Include
		neverInclude    : [ "password" ]
	};

	/**
	 * --------------------------------------------------------------------------
	 * Population Control
	 * --------------------------------------------------------------------------
	 * https://coldbox.ortusbooks.com/readme/release-history/whats-new-with-7.0.0#population-enhancements
	 */
	this.population = {
		include : [], // if empty, tries to include them all
		exclude : [ "permissions", "roles" ] // These are not mass assignable
	}

	/**
	 * Constructor
	 */
	function init(){
		variables.id          = "";
		variables.firstName   = "";
		variables.lastName    = "";
		variables.username    = "";
		variables.password    = "";
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

}
