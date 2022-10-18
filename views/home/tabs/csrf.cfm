<cfoutput>
	<div>

		<h2>CSRF Settings</h2>
		<p>These settings are used by the <code>cbcsrf</code> module, you can find much more information about it <a href="https://github.com/coldbox-modules/cbcsrf" target="_blank">here</a>.</p>

		<ul class="list-group mt-3">
			<li class="list-group-item d-flex justify-content-between align-items-center">
				<span class="fw-semibold w-25 text-secondary">Cache Storage</span>
				<span class="flex-grow-1">
					<code>#prc.settings.csrf.cacheStorage#</code>
				</span>
			</li>

			<li class="list-group-item d-flex justify-content-between align-items-center">
				<span class="fw-semibold w-25 text-secondary">Auth Token Rotator</span>
				<span class="flex-grow-1">
					<div
						class="form-check form-switch"
						data-bs-placement="left"
						data-bs-toggle="tooltip"
						data-bs-title="#prc.settings.csrf.enableAuthTokenRotator ? 'Enabled' : 'Disabled'#"
					>
						<input
							class="form-check-input opacity-100"
							disabled
							type="checkbox"
							<cfif prc.settings.csrf.enableAuthTokenRotator>
								checked="checked"
							</cfif>
							role="switch"
							id="flexSwitchCheckDefault">
					</div>
				</span>
			</li>

			<li class="list-group-item d-flex justify-content-between align-items-center">
				<span class="fw-semibold w-25 text-secondary">Auto Verifier</span>
				<span class="flex-grow-1">
					<div
						class="form-check form-switch"
						data-bs-placement="left"
						data-bs-toggle="tooltip"
						data-bs-title="#prc.settings.csrf.enableAutoVerifier ? 'Enabled' : 'Disabled'#"
					>
						<input
							class="form-check-input opacity-100"
							disabled
							type="checkbox"
							<cfif prc.settings.csrf.enableAutoVerifier>
								checked="checked"
							</cfif>
							role="switch"
							id="flexSwitchCheckDefault">
					</div>
				</span>
			</li>

			<li class="list-group-item d-flex justify-content-between align-items-center">
				<span class="fw-semibold w-25 text-secondary">CSRF Endpoint Generator</span>
				<span class="flex-grow-1">
					<div
						class="form-check form-switch"
						data-bs-placement="left"
						data-bs-toggle="tooltip"
						data-bs-title="#prc.settings.csrf.enableEndpoint ? 'Enabled' : 'Disabled'#"
					>
						<input
							class="form-check-input opacity-100"
							disabled
							type="checkbox"
							<cfif prc.settings.csrf.enableEndpoint>
								checked="checked"
							</cfif>
							role="switch"
							id="flexSwitchCheckDefault">
					</div>
				</span>
			</li>

			<li class="list-group-item d-flex justify-content-between align-items-center">
				<span class="fw-semibold w-25 text-secondary">Rotation Timeout</span>
				<span class="flex-grow-1">
					<code>#prc.settings.csrf.rotationTimeout#</code>
				</span>
			</li>

			<li class="list-group-item d-flex justify-content-between align-items-center">
				<span class="fw-semibold w-25 text-secondary">Event Exclusions</span>
				<span class="flex-grow-1">
					<code>#serializeJSON( prc.settings.csrf.verifyExcludes )#</code>
				</span>
			</li>
		</ul>

	</div>
	</cfoutput>
