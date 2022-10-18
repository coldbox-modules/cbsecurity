<cfoutput>
<h1 class="display-4">ColdBox Security Visualizer</h1>

<p class="lead">From here you can inspect the way <code>cbSecurity</code> is configured for your application.</p>

<div class="d-flex align-items-start">
	<ul class="nav flex-column w-25 nav-pills" role="tablist" aria-orientation="vertical">
		<!--- Authentication --->
		<li class="nav-item p-1" role="presentation">
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
				<i class="m-2 bi bi-door-open"></i> Authentication
			</a>
		</li>
		<!--- Basic Auth --->
		<li class="nav-item p-1" role="presentation">
			<a
				class="nav-link"
				id="basicAuth-tab"
				data-bs-toggle="tab"
				data-bs-target="##basicAuth-pane"
				aria-controls="basicAuth-pane"
				aria-selected="true"
				role="tab"
				href="##basicAuth"
			>
				<i class="m-2 bi bi-person-bounding-box"></i> Basic Auth
			</a>
		</li>
		<!--- CSRF --->
		<li class="nav-item p-1" role="presentation">
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
				<i class="m-2 bi bi-bezier2"></i> CSRF
			</a>
		</li>
		<!--- Firewall Settings --->
		<li class="nav-item p-1" role="presentation">
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
				<i class="m-2 bi bi-bricks"></i> Firewall
			</a>
		</li>
		<!--- Firewall Rules --->
		<li class="nav-item p-1" role="presentation">
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
				<i class="m-2 bi bi-file-ruled-fill"></i> Firewall Rules
			</a>
		</li>
		<!--- JWT --->
		<li class="nav-item p-1" role="presentation">
			<a
				class="nav-link"
				id="jwt-tab"
				data-bs-toggle="tab"
				data-bs-target="##jwt-pane"
				aria-controls="jwt-pane"
				aria-selected="true"
				role="tab"
				href="##jwt"
			>
				<i class="m-2 bi bi-filetype-json"></i> JWT
			</a>
		</li>
		<!--- Security Headers --->
		<li class="nav-item p-1" role="presentation">
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
				<i class="m-2 bi bi-shield-exclamation"></i> Security Headers
			</a>
		</li>
	</ul>

	<div class="tab-content w-100 ms-4 me-2">
		<div class="tab-pane fade show active" id="authentication-pane" role="tabpanel" aria-labelledby="authentication-tab" tabindex="0">
			#renderView(
				view = "home/tabs/authentication",
				module = "cbsecurity"
			)#
		</div>
		<div class="tab-pane fade show" id="basicAuth-pane" role="tabpanel" aria-labelledby="basicAuth-tab" tabindex="0">
			#renderView(
				view = "home/tabs/basicAuth",
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

</div>

</cfoutput>
