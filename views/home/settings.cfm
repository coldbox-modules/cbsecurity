<cfscript>
	globalSettings = prc.settings.filter( function( key ){
		return !listFindNoCase( "rules,jwt", key );
	} );
	jwtSettings = prc.settings.jwt.filter( function( key ){
		return !listFindNoCase( "secretKey", key );
	} );
</cfscript>
<cfoutput>
<div class="mt-2">

	<cfdump var="#globalSettings#">

	<h2>JWT Settings</h2>
	<p>Here are your settings for your Json Web Tokens Security. Please note your <code>secretKey</code> is not shown.</p>
	<cfdump var="#jwtSettings#">

</div>
</cfoutput>
