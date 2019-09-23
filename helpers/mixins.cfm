<cfscript>
	function jwt() {
        return wirebox.getInstance( "JwtService@cbSecurity" );
    }
</cfscript>