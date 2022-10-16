<cfoutput>
	<div class="m-4">

		<h2>Global Settings</h2>

		<ul class="list-group mt-3 mb-3">

			<li class="list-group-item d-flex justify-content-between align-items-center">
				<span class="fw-semibold w-25 text-secondary">Autoload Firewall</span>
				<span class="flex-grow-1">
					<div
						class="form-check form-switch"
						data-bs-placement="left"
						data-bs-toggle="tooltip"
						data-bs-title="#prc.settings.firewall.autoLoadFirewall ? 'Enabled' : 'Disabled'#"
					>
						<input
							class="form-check-input opacity-100"
							disabled
							type="checkbox"
							<cfif prc.settings.firewall.autoLoadFirewall>
								checked="checked"
							</cfif>
							role="switch"
							id="flexSwitchCheckDefault">
					</div>
				</span>
			</li>

			<li class="list-group-item d-flex justify-content-between align-items-center">
				<span class="fw-semibold w-25 text-secondary">Handler Annotation Security</span>
				<span class="flex-grow-1">
					<div
						class="form-check form-switch"
						data-bs-placement="left"
						data-bs-toggle="tooltip"
						data-bs-title="#prc.settings.firewall.handlerAnnotationSecurity ? 'Enabled' : 'Disabled'#"
					>
						<input
							class="form-check-input opacity-100"
							disabled
							type="checkbox"
							<cfif prc.settings.firewall.handlerAnnotationSecurity>
								checked="checked"
							</cfif>
							role="switch"
							id="flexSwitchCheckDefault">
					</div>
				</span>
			</li>

			<li class="list-group-item d-flex justify-content-between align-items-center">
				<span class="fw-semibold w-25 text-secondary">Global Validator</span>
				<span class="flex-grow-1">
					<code>#prc.settings.firewall.validator#</code>
				</span>
			</li>

			<li class="list-group-item d-flex justify-content-between align-items-center">
				<span class="fw-semibold w-25 text-secondary">Default Authentication Action</span>
				<span class="flex-grow-1">
					<code>#prc.settings.firewall.defaultAuthenticationAction#</code>
					<i class="bi bi-chevron-double-right"></i>
					<code>#prc.settings.firewall.invalidAuthenticationEvent#</code>
				</span>
			</li>

			<li class="list-group-item d-flex justify-content-between align-items-center">
				<span class="fw-semibold w-25 text-secondary">Default Authorization Action</span>
				<span class="flex-grow-1">
					<code>#prc.settings.firewall.defaultAuthorizationAction#</code>
					<i class="bi bi-chevron-double-right"></i>
					<code>#prc.settings.firewall.invalidAuthorizationEvent#</code>
				</span>
			</li>

		</ul>

		<h2>Rule Settings</h2>

		<ul class="list-group mt-3 mb-3">
			<li class="list-group-item d-flex justify-content-between align-items-center">
				<span class="fw-semibold w-25 text-secondary">Use Regular Expressions</span>
				<span class="flex-grow-1">
					<div
						class="form-check form-switch"
						data-bs-placement="left"
						data-bs-toggle="tooltip"
						data-bs-title="#prc.settings.firewall.rules.useRegex ? 'Enabled' : 'Disabled'#"
					>
						<input
							class="form-check-input opacity-100"
							disabled
							type="checkbox"
							<cfif prc.settings.firewall.rules.useRegex>
								checked="checked"
							</cfif>
							role="switch"
							id="flexSwitchCheckDefault">
					</div>
				</span>
			</li>

			<li class="list-group-item d-flex justify-content-between align-items-center">
				<span class="fw-semibold w-25 text-secondary">Use SSL Relocations</span>
				<span class="flex-grow-1">
					<div
						class="form-check form-switch"
						data-bs-placement="left"
						data-bs-toggle="tooltip"
						data-bs-title="#prc.settings.firewall.rules.useSSL ? 'Enabled' : 'Disabled'#"
					>
						<input
							class="form-check-input opacity-100"
							disabled
							type="checkbox"
							<cfif prc.settings.firewall.rules.useSSL>
								checked="checked"
							</cfif>
							role="switch"
							id="flexSwitchCheckDefault">
					</div>
				</span>
			</li>

			<li class="list-group-item d-flex justify-content-between align-items-center">
				<span class="fw-semibold w-25 text-secondary">Rule Defaults</span>
				<span class="flex-grow-1">
					<code>#serializeJSON( prc.settings.firewall.rules.defaults )#</code>
				</span>
			</li>
		</ul>

		<h2>Registered Modules</h2>
		<p>The following are modules that have incorporated their own security rules or settings</p>

		<table class="table table-hover">
			<thead>
				<tr>
					<th width="200">Module</th>
					<th>Settings</th>
				</tr>
			</thead>
			<tbody>
				<cfloop array="#prc.settings.securityModules.keyArray()#" index="thisModule">
					<tr>
						<td class="fw-semibold">
							#thisModule#
						</td>
						<td>
							<ul class="list-group mt-3 mb-3">

								<li class="list-group-item d-flex justify-content-between align-items-center">
									<span class="fw-semibold w-25 text-secondary">Module Validator</span>
									<span class="flex-grow-1">
										<cfif len( prc.settings.securityModules[ thisModule ].firewall.validator )>
											<code>#prc.settings.securityModules[ thisModule ].firewall.validator#</code>
										<cfelse>
											<code><< Global Validator >></code>
										</cfif>
									</span>
								</li>

								<li class="list-group-item d-flex justify-content-between align-items-center">
									<span class="fw-semibold w-25 text-secondary">Default Authentication Action</span>
									<span class="flex-grow-1">
										<cfif len( prc.settings.securityModules[ thisModule ].firewall.defaultAuthenticationAction )>
											<code>#prc.settings.securityModules[ thisModule ].firewall.defaultAuthenticationAction#</code>
										<cfelse>
											<code><< Global Default >></code>
										</cfif>
										<i class="bi bi-chevron-double-right"></i>
										<code>#prc.settings.securityModules[ thisModule ].firewall.invalidAuthenticationEvent#</code>
									</span>
								</li>

								<li class="list-group-item d-flex justify-content-between align-items-center">
									<span class="fw-semibold w-25 text-secondary">Default Authorization Action</span>
									<span class="flex-grow-1">
										<cfif len( prc.settings.securityModules[ thisModule ].firewall.defaultAuthorizationAction )>
											<code>#prc.settings.securityModules[ thisModule ].firewall.defaultAuthorizationAction#</code>
										<cfelse>
											<code><< Global Default >></code>
										</cfif>
										<i class="bi bi-chevron-double-right"></i>
										<code>#prc.settings.securityModules[ thisModule ].firewall.invalidAuthorizationEvent#</code>
									</span>
								</li>

								<li class="list-group-item d-flex justify-content-between align-items-center">
									<span class="fw-semibold w-25 text-secondary">Rule Defaults</span>
									<span class="flex-grow-1">
										<code>#serializeJSON( prc.settings.securityModules[ thisModule ].firewall.rules.defaults )#</code>
									</span>
								</li>

								<li class="list-group-item d-flex justify-content-between align-items-center">
									<span class="fw-semibold w-25 text-secondary">Rule Provider</span>
									<span class="flex-grow-1">
										<code>#serializeJSON( prc.settings.securityModules[ thisModule ].firewall.rules.provider )#</code>
									</span>
								</li>

								<li class="list-group-item d-flex justify-content-between align-items-center">
									<span class="fw-semibold w-25 text-secondary">Rules</span>
									<span class="flex-grow-1">
										<code>#arrayLen( prc.settings.securityModules[ thisModule ].firewall.rules.inline )#</code>
									</span>
								</li>

							</ul>

						</td>
					</tr>
				</cfloop>
			</tbody>
		</table>


	</div>
</cfoutput>
