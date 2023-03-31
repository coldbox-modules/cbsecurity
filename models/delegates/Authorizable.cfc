/**
 * Copyright since 2016 by Ortus Solutions, Corp
 * www.ortussolutions.com
 * ---
 * This delegate allows for objects to verify permissions and roles on the $parent
 * This delegate expects the following functions to be exposed in the $parent
 * and they must return an array of values
 *
 * - getPermissions()
 * - getRoles()
 * - getId()
 */
component {

	// DI
	property name="cbSecurity" inject="cbSecurity@cbSecurity";

	/***************************************************************/
	/* IAuthUser Methods
	/***************************************************************/

	/**
	 * Verify if the parent has one or more of the passed in permissions
	 *
	 * @permission One or a list of permissions to check for access
	 */
	boolean function hasPermission( required permission ){
		return arrayWrap( arguments.permission )
			.filter( function( item ){
				return ( $parent.getPermissions().findNoCase( item ) );
			} )
			.len();
	}

	/**
	 * Verify if the parent has one or more of the passed in roles
	 *
	 * @role One or a list of roles to check for access
	 */
	boolean function hasRole( required role ){
		return arrayWrap( arguments.role )
			.filter( function( item ){
				return ( $parent.getRoles().findNoCase( item ) );
			} )
			.len();
	}

	/**
	 * Verify if the current user is logged in or not.
	 */
	function isLoggedIn(){
		return variables.cbSecurity.isLoggedIn();
	}

	/**
	 * Verifies if a user is NOT logged in
	 */
	boolean function guest(){
		return variables.cbSecurity.guest();
	}

	/***************************************************************/
	/* Verification Methods
	/***************************************************************/

	/**
	 * Verify that ALL the permissions passed must exist within the authenticated user
	 *
	 * @permissions One, a list or an array of permissions
	 *
	 * @throws NoUserLoggedIn
	 */
	boolean function hasAll( required permissions ){
		var aPerms = arrayWrap( arguments.permissions );

		return aPerms
			.filter( function( item ){
				return $parent.hasPermission( arguments.item );
			} )
			.len() == aPerms.len();
	}

	/**
	 * Verify that NONE of the permissions passed must exist within the authenticated user
	 *
	 * @permissions One, a list or an array of permissions
	 *
	 * @throws NoUserLoggedIn
	 */
	boolean function hasNone( required permissions ){
		return arrayWrap( arguments.permissions )
			.filter( function( item ){
				return $parent.hasPermission( arguments.item );
			} )
			.len() == 0;
	}

	/**
	 * Verify that the passed in user object must be the same as the authenticated user
	 * Equality is done by evaluating the `getid()` method on both objects.
	 *
	 * @user The user to test for equality
	 *
	 * @throws NoUserLoggedIn
	 */
	boolean function sameUser( required user ){
		return ( arguments.user.getId() == $parent.getId() );
	}

	/**
	 * convert one or a list of permissions to an array, if it's an array we don't touch it
	 *
	 * @items One, a list or an array
	 *
	 * @return An array
	 */
	private array function arrayWrap( required items ){
		return isArray( arguments.items ) ? arguments.items : listToArray( arguments.items );
	}

}
