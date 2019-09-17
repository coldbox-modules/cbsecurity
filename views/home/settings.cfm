<cfoutput>
<div class="mt-2">

	<p>Here is a listing of the settings for the global interceptor <code>cbsecurity@global</code>:</p>

	<cfdump var="#prc.properties.filter( function( key ){
		return key != "rules";
	} )#">

</div>
</cfoutput>