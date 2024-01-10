<cfoutput>
<h1>Module Tester</h1>


<!--- should should be singleton --->
<cfset cbs = wirebox.getInstance( "cbSecurity@cbSecurity" ) />
cbSecurity remote IP : #cbs.getRealIP()#<br/>
You are #cbSecure().isLoggedIn() ? '' : '<span style="color:red">NOT</span>'# logged in 

<div>
	#renderView()#
</div>
</cfoutput>