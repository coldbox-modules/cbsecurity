<cfscript>
	/**
	 * Retrieve the Jwt Auth Service
	 */
	function jwtAuth() {
        return wirebox.getInstance( "JwtService@cbSecurity" );
	}

	/**
	 * Retrieve the CBSecurity Service Object
	 */
	function cbSecure() {
        return wirebox.getInstance( "CBSecurity@cbSecurity" );
	}
</cfscript>
