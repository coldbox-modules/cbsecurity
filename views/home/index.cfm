<cfoutput>
<h1 class="display-4">ColdBox Security Visualizer</h1>

<p class="lead">From here you can inspect the way cbSecurity is configured for your application.</p>

<ul class="nav nav-tabs" role="tablist">
	<!--- Authentication --->
	<li class="nav-item" role="presentation">
		<a
			class="nav-link active"
			id="authentication-tab"
			data-bs-toggle="tab"
			data-bs-target="##authentication-pane"
			aria-controls="authentication-pane"
			aria-selected="true"
			role="tab"
			href="##authentication"
		>
			Authentication
		</a>
	</li>
	<!--- CSRF --->
	<li class="nav-item" role="presentation">
		<a
			class="nav-link"
			id="csrf-tab"
			data-bs-toggle="tab"
			data-bs-target="##csrf-pane"
			aria-controls="csrf-pane"
			aria-selected="true"
			role="tab"
			href="##csrf"
		>
			CSRF
		</a>
	</li>
	<!--- Firewall Settings --->
	<li class="nav-item" role="presentation">
		<a
			class="nav-link"
			id="firewall-tab"
			data-bs-toggle="tab"
			data-bs-target="##firewall-pane"
			aria-controls="firewall-pane"
			aria-selected="true"
			role="tab"
			href="##firewall"
		>
			Firewall
		</a>
	</li>
	<!--- Firewall Rules --->
	<li class="nav-item" role="presentation">
		<a
			class="nav-link"
			id="rules-tab"
			data-bs-toggle="tab"
			data-bs-target="##rules-pane"
			aria-controls="rules-pane"
			aria-selected="true"
			role="tab"
			href="##rules"
		>
			Firewall Rules
		</a>
	</li>
	<!--- JWT --->
	<li class="nav-item" role="presentation">
		<a
			class="nav-link"
			id="JWT-tab"
			data-bs-toggle="tab"
			data-bs-target="##JWT-pane"
			aria-controls="JWT-pane"
			aria-selected="true"
			role="tab"
			href="##JWT"
		>
			JWT
		</a>
	</li>
	<!--- Security Headers --->
	<li class="nav-item" role="presentation">
		<a
			class="nav-link"
			id="security-headers-tab"
			data-bs-toggle="tab"
			data-bs-target="##security-headers-pane"
			aria-controls="security-headers-pane"
			aria-selected="true"
			role="tab"
			href="##security-headers"
		>
			Security Headers
		</a>
	</li>

</ul>

<div class="tab-content">
	<div class="tab-pane fade show active" id="authentication-pane" role="tabpanel" aria-labelledby="authentication-tab" tabindex="0">
		#renderView(
			view = "home/tabs/authentication",
			module = "cbsecurity"
		)#
	</div>
	<div class="tab-pane fade show" id="csrf-pane" role="tabpanel" aria-labelledby="csrf-tab" tabindex="0">
		#renderView(
			view = "home/tabs/csrf",
			module = "cbsecurity"
		)#
	</div>
	<div class="tab-pane fade show" id="firewall-pane" role="tabpanel" aria-labelledby="firewall-tab" tabindex="0">
		#renderView(
			view = "home/tabs/firewall",
			module = "cbsecurity"
		)#
	</div>
	<div class="tab-pane fade show" id="rules-pane" role="tabpanel" aria-labelledby="rules-tab" tabindex="0">
		#renderView(
			view = "home/tabs/rules",
			module = "cbsecurity"
		)#
	</div>
	<div class="tab-pane fade show" id="jwt-pane" role="tabpanel" aria-labelledby="jwt-tab" tabindex="0">
		#renderView(
			view = "home/tabs/jwt",
			module = "cbsecurity"
		)#
	</div>
	<div class="tab-pane fade show" id="security-headers-pane" role="tabpanel" aria-labelledby="security-headers-tab" tabindex="0">
		#renderView(
			view = "home/tabs/security-headers",
			module = "cbsecurity"
		)#
	</div>
</div>

<cfdump var="#prc.settings#">

</cfoutput>
