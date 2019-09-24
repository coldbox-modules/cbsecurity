<cfscript>
	function jwtAuth() {
        return wirebox.getInstance( "JwtService@cbSecurity" );
    }
</cfscript>