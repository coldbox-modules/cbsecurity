<cfoutput>
<div>

	<h2>JWT Settings</h2>
	<p>These settings are used by the <code>jwt + cbsecurity</code> module.</p>

	<ul class="list-group mt-3 mb-5">
		<li class="list-group-item d-flex justify-content-between align-items-center">
			<span class="fw-semibold w-25 text-secondary">Encryption Algorithm</span>
			<span class="flex-grow-1">
				<code>#prc.settings.jwt.algorithm#</code>
			</span>
		</li>

		<li class="list-group-item d-flex justify-content-between align-items-center">
			<span class="fw-semibold w-25 text-secondary">Default Expiration</span>
			<span class="flex-grow-1">
				<code>#prc.settings.jwt.expiration#</code>
			</span>
		</li>

		<li class="list-group-item d-flex justify-content-between align-items-center">
			<span class="fw-semibold w-25 text-secondary">Default Issuer</span>
			<span class="flex-grow-1">
				<code>#prc.settings.jwt.issuer#</code>
			</span>
		</li>

		<li class="list-group-item d-flex justify-content-between align-items-center">
			<span class="fw-semibold w-25 text-secondary">Required Claims</span>
			<span class="flex-grow-1">
				<code>#serializeJSON( prc.settings.jwt.requiredClaims )#</code>
			</span>
		</li>

		<li class="list-group-item d-flex justify-content-between align-items-center">
			<span class="fw-semibold w-25 text-secondary">Authentication Header</span>
			<span class="flex-grow-1">
				<code>#prc.settings.jwt.customAuthHeader#</code>
			</span>
		</li>

		<li class="list-group-item d-flex justify-content-between align-items-center">
			<span class="fw-semibold w-25 text-secondary">Refresh Tokens</span>
			<span class="flex-grow-1">
				<div
					class="form-check form-switch"
					data-bs-placement="left"
					data-bs-toggle="tooltip"
					data-bs-title="#prc.settings.jwt.enableRefreshTokens ? 'Enabled' : 'Disabled'#"
				>
					<input
						class="form-check-input opacity-100"
						disabled
						type="checkbox"
						<cfif prc.settings.jwt.enableRefreshTokens>
							checked="checked"
						</cfif>
						role="switch"
						id="flexSwitchCheckDefault">
				</div>
			</span>
		</li>

		<li class="list-group-item d-flex justify-content-between align-items-center">
			<span class="fw-semibold w-25 text-secondary">Refresh Expiration</span>
			<span class="flex-grow-1">
				<code>#prc.settings.jwt.refreshExpiration#</code>
			</span>
		</li>

		<li class="list-group-item d-flex justify-content-between align-items-center">
			<span class="fw-semibold w-25 text-secondary">Refresh Tokens Endpoint</span>
			<span class="flex-grow-1">
				<div
					class="form-check form-switch"
					data-bs-placement="left"
					data-bs-toggle="tooltip"
					data-bs-title="#prc.settings.jwt.enableRefreshEndpoint ? 'Enabled' : 'Disabled'#"
				>
					<input
						class="form-check-input opacity-100"
						disabled
						type="checkbox"
						<cfif prc.settings.jwt.enableRefreshEndpoint>
							checked="checked"
						</cfif>
						role="switch"
						id="flexSwitchCheckDefault">
				</div>
			</span>
		</li>

		<li class="list-group-item d-flex justify-content-between align-items-center">
			<span class="fw-semibold w-25 text-secondary">Refresh Header</span>
			<span class="flex-grow-1">
				<code>#prc.settings.jwt.customRefreshHeader#</code>
			</span>
		</li>

	</ul>

	<h2>Token Storage</h2>

	<ul class="list-group mt-3 mb-5">

		<li class="list-group-item d-flex justify-content-between align-items-center">
			<span class="fw-semibold w-25 text-secondary">Storage Enabled</span>
			<span class="flex-grow-1">
				<div
					class="form-check form-switch"
					data-bs-placement="left"
					data-bs-toggle="tooltip"
					data-bs-title="#prc.settings.jwt.tokenStorage.enabled ? 'Enabled' : 'Disabled'#"
				>
					<input
						class="form-check-input opacity-100"
						disabled
						type="checkbox"
						<cfif prc.settings.jwt.tokenStorage.enabled>
							checked="checked"
						</cfif>
						role="switch"
						id="flexSwitchCheckDefault">
				</div>
			</span>
		</li>

		<li class="list-group-item d-flex justify-content-between align-items-center">
			<span class="fw-semibold w-25 text-secondary">Storage Driver</span>
			<span class="flex-grow-1">
				<code>#prc.settings.jwt.tokenStorage.driver#</code>
			</span>
		</li>

		<li class="list-group-item d-flex justify-content-between align-items-center">
			<span class="fw-semibold w-25 text-secondary">Storage Driver Properties</span>
			<span class="flex-grow-1">
				<code>#serializeJSON( prc.settings.jwt.tokenStorage.properties )#</code>
			</span>
		</li>

		<li class="list-group-item d-flex justify-content-between align-items-center">
			<span class="fw-semibold w-25 text-secondary">Storage Key Prefix</span>
			<span class="flex-grow-1">
				<code>#prc.settings.jwt.tokenStorage.keyPrefix#</code>
			</span>
		</li>

	</ul>
</div>
</cfoutput>
