component accessors="true" implements="cbsecurity.interfaces.jwt.IJwtSubject" {

	property name="auth" inject="authenticationService@cbauth";

	property name="id";
	property name="firstName";
	property name="lastName";
	property name="username";
	property name="password";

	function init(){
		variables.id        = "";
		variables.firstName = "";
		variables.lastName  = "";
		variables.username  = "";
		variables.password  = "";

		variables.permissions = [ "write", "read" ];

		return this;
	}

	boolean function isLoaded(){
		return ( !isNull( variables.id ) && len( variables.id ) );
	}

	/**
	 * A struct of custom claims to add to the JWT token
	 */
	struct function getJWTCustomClaims( required struct payload ){
		return {
			"duplicatedJTI": arguments.payload.jti,
			"role" : "admin"
		};
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
	 *
	 */
	boolean function hasPermission( required permission ){
		if ( isSimpleValue( arguments.permission ) ) {
			arguments.permission = listToArray( arguments.permission );
		}

		return arguments.permission
			.filter( function(item){
				return ( variables.permissions.findNoCase( item ) );
			} )
			.len();
	}

}
