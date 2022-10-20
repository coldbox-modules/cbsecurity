<cfoutput>
<h1>Security Login</h1>

<ul>
	<li><a href="/main/index">Home</a></li>
</ul>

<cfif flash.exists( "message" )>
	<div style="border: 1px solid gray; background-color: ##f29595; margin: 20px 0px; padding: 10px">
		#flash.get( "message" )#
	</div>
</cfif>

#html.startForm( action="main.doLogin" )#

	#html.textField( name="username", placeholder="username" )#
	<br>
	#html.passwordField( name="password", placeholder="password" )#
	<br>
	#html.submitButton( name="Submit" )#

#html.endForm()#
</cfoutput>
