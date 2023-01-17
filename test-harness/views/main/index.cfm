<cfoutput>
<h1>CBSecurity</h1>

<p>This is the public homepage</p>

<ul>
	<cfif cbsecure().isLoggedIn()>
		<li>
			<a href="/main/doLogout">Logout</a>
		</li>
	<cfelse>
		<li>
			<a href="/main/login">Login</a>
		</li>
	</cfif>

	<li>
		<a href="/cbsecurity">Visualizer</a>
	</li>

	<li>
		<a href="/admin">Admin Access Test</a>
	</li>
	<li>
		<a href="/putpost">PUT/POST Rejection</a>
	</li>
	<li>
		<a href="/noAction">Secure No Action</a>
	</li>
	<li>
		<a href="/ruleActionOverride">Secure Rule Action Override</a>
	</li>
	<li>
		<a href="/override">Secure Rule Direct Action</a>
	</li>
</ul>
</cfoutput>
