<cfoutput>
<h1>Security Login</h1>

#html.startForm( action="main.doLogin" )#

	#html.textField( name="username", placeholder="username" )#
	<br>
	#html.passwordField( name="password", placeholder="password" )#
	<br>
	#html.submitButton( name="Submit" )#

#html.endForm()#
</cfoutput>