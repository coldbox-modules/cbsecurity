<cfoutput>
<p class="lead mb-4">
	Welcome to the <span class="fw-semibold">ColdBox Security Visualizer</span>. From here you can view your firewall activity, settings and much more.
</p>

<div class="d-flex align-items-start mt-3">
	<ul class="nav flex-column w-25 nav-pills" role="tablist" aria-orientation="vertical">
		<!--- Activity --->
		<li class="nav-item p-1" role="presentation">
			<a
				class="nav-link active"
				id="activity-tab"
				data-bs-toggle="tab"
				data-bs-target="##activity-pane"
				aria-controls="activity-pane"
				aria-selected="true"
				role="tab"
				href="##activity"
				title="activity"
			>
				<i class="m-2 bi bi-activity"></i> <span class="d-none d-lg-inline">Activity</span>
			</a>
		</li>
		<!--- Authentication --->
		<li class="nav-item p-1" role="presentation">
			<a
				class="nav-link"
				id="authentication-tab"
				data-bs-toggle="tab"
				data-bs-target="##authentication-pane"
				aria-controls="authentication-pane"
				aria-selected="true"
				role="tab"
				href="##authentication"
				title="Authentication"
			>
				<i class="m-2 bi bi-door-open"></i> <span class="d-none d-lg-inline">Authentication</span>
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
				title="Basic Auth"
			>
				<i class="m-2 bi bi-person-bounding-box"></i> <span class="d-none d-lg-inline">Basic Auth</span>
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
				title="CSRF"
			>
				<i class="m-2 bi bi-bezier2"></i> <span class="d-none d-lg-inline">CSRF</span>
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
				title="Firewall"
			>
				<i class="m-2 bi bi-bricks"></i> <span class="d-none d-lg-inline">Firewall</span>
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
				title="Firewall Rules"
			>
				<i class="m-2 bi bi-sort-down"></i> <span class="d-none d-lg-inline">Firewall Rules</span>
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
				title="JWT"
			>
				<i class="m-2 bi bi-filetype-json"></i> <span class="d-none d-lg-inline">JWT</span>
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
				title="Security Headers"
			>
				<i class="m-2 bi bi-shield-exclamation"></i> <span class="d-none d-lg-inline">Security Headers</span>
			</a>
		</li>
	</ul>

	<div class="tab-content w-100 ms-5 me-2">
		<div class="tab-pane fade show active" id="activity-pane" role="tabpanel" aria-labelledby="activity-tab" tabindex="0">
			#renderView(
				view = "home/tabs/activity",
				module = "cbsecurity"
			)#
		</div>
		<div class="tab-pane fade show" id="authentication-pane" role="tabpanel" aria-labelledby="authentication-tab" tabindex="0">
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
