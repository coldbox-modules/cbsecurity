/**
 * Copyright since 2016 by Ortus Solutions, Corp
 * www.ortussolutions.com
 * ---
 * This is a JWT authentication validator.  It is in charge of validating rules and annotations
 * against an incoming JWT token.
 */
component singleton threadsafe {

	// Injection
	property name="jwtService"     inject="JwtService@cbSecurity";
	property name="requestService" inject="coldbox:requestService";
	property name="cbsecurity"     inject="@cbSecurity";

	/**
	 * This function is called once an incoming event matches a security rule.
	 * You will receive the security rule that matched and an instance of the
	 * ColdBox controller.
	 *
	 * allow : True, user can continue access, false, invalid access actions will ensue
	 * type : Is the issue an authentication or an authorization issue.
	 *
	 * @return { allow:boolean, type:authentication|authorization }
	 */
	struct function ruleValidator( required rule, required controller ){
		return validateSecurity( arguments.rule.permissions );
	}

	/**
	 * This function is called once access to a handler/action is detected.
	 * You will receive the secured annotation value and an instance of the ColdBox Controller
	 *
	 * You must return a struct with two keys:
	 * - allow:boolean True, user can continue access, false, invalid access actions will ensue
	 * - type:string(authentication|authorization) The type of block that ocurred.  Either an authentication or an authorization issue.
	 *
	 * @return { allow:boolean, type:string(authentication|authorization) }
	 */
	struct function annotationValidator( required securedValue, required controller ){
		return validateSecurity( arguments.securedValue );
	}

	/**
	 * Validate Security for the jwt token called by an annotation or rule validation event
	 *
	 * @permissions The permissions we want to validate in the scopes
	 */
	function validateSecurity( required permissions ){
		var jwtSettings = variables.jwtService.getSettings().jwt;
		// Prepare results packet
		var results     = {
			"allow"    : false,
			"type"     : "authentication",
			"messages" : ""
		};

		var payload = {};

		try {
			try {
				// Try to get the payload from the jwt token, if we have exceptions, we have failed :(
				// This takes care of authenticating the jwt tokens for us.
				// getPayload() => parseToken() => authenticateToken()
				payload = variables.jwtService.getPayload();
			} catch ( any e ) {
				// if we aren't trying to refresh, return the false response now.
				var refreshToken = variables.jwtService.discoverRefreshToken();
				if (
					!jwtSettings.enableAutoRefreshValidator ||
					!len( refreshToken ) ||
					!listFindNoCase( "TokenExpiredException,TokenInvalidException,TokenNotFoundException", e.type )
				) {
					results.messages = e.type & ":" & e.message;
					return results;
				}

				// Try to Refresh the tokens
				var newTokens = variables.jwtService.refreshToken( refreshToken );
				// Setup payload + authenticate for current request
				payload       = variables.jwtService.parseToken( newTokens.access_token );
				// Send back as headers now that they are refreshed
				variables.requestService
					.getContext()
					.setHTTPHeader( name: jwtSettings.customAuthHeader, value: newTokens.access_token )
					.setHTTPHeader( name: jwtSettings.customRefreshHeader, value: newTokens.refresh_token );
			}
		}
		// All exceptions for refreshTokens
		catch ( Any e ) {
			results.messages = e.type & ":" & e.message;
			return results;
		}

		// Are we logged in?
		if ( variables.cbSecurity.getAuthService().isLoggedIn() ) {
			// Do we have any permissions to validate?
			if ( listLen( arguments.permissions ) ) {
				// Check if the user has the right permissions?
				results.allow = (
					tokenHasScopes( arguments.permissions, payload.scope )
					||
					variables.cbSecurity.has( arguments.permissions )
				);
				results.type = "authorization";
			} else {
				// We are satisfied!
				results.allow = true;
			}
		}

		return results;
	}

	/**
	 * Verify if the jwt token has the appropriate scopes
	 *
	 * @permission A list of permissions to validate within a token
	 * @scopes     A space delimited string of scopes
	 */
	private boolean function tokenHasScopes( required permission, required scopes ){
		if ( isSimpleValue( arguments.permission ) ) {
			arguments.permission = listToArray( arguments.permission );
		}

		return arguments.permission
			.filter( function( item ){
				return ( scopes.listfindNoCase( item, " " ) );
			} )
			.len();
	}

}
