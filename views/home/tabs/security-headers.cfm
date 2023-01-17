<cfoutput>
	<div>

		<h2>Security Header Settings</h2>

		<ul class="list-group mt-3 mb-5">
			<li class="list-group-item d-flex justify-content-between align-items-center">
				<span class="w-50 me-2">
					<div class="text-secondary fw-semibold">Trust Upstream</div>
					<small class="text-muted">
						If you trust the upstream, then we will inspect any <code>x-forwarded-{}</code>
						headers first, else we rely on the traditional header inspection.
					</small>
				</span>
				<span class="flex-grow-1 ms-2">
					<div
						class="form-check form-switch"
						data-bs-placement="left"
						data-bs-toggle="tooltip"
						data-bs-title="#prc.settings.securityHeaders.trustUpstream ? 'Yes' : 'No'#"
					>
						<input
							class="form-check-input opacity-100"
							disabled
							type="checkbox"
							<cfif prc.settings.securityHeaders.trustUpstream>
								checked="checked"
							</cfif>
							role="switch"
							id="flexSwitchCheckDefault">
					</div>
				</span>
			</li>

			<li class="list-group-item d-flex justify-content-between align-items-center">
				<span class="w-50">
					<div class="text-secondary fw-semibold">
						Host Header Validation
						<a href="https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/host" target="_blank">
							<i class="bi bi-info-circle-fill"></i>
						</a>
					</div>
					<small class="text-muted">
						This header validates the incoming host or forwarded host against a valid list of allowed hosts.
						If not, the firewall will block the request with a <code>403 : Not Authorized</code> response.
					</small>
				</span>
				<span class="flex-grow-1 ms-2">
					<div
						class="form-check form-switch"
						data-bs-placement="left"
						data-bs-toggle="tooltip"
						data-bs-title="#prc.settings.securityHeaders.hostHeaderValidation.enabled ? 'Enabled' : 'Disabled'#"
					>
						<input
							class="form-check-input opacity-100"
							disabled
							type="checkbox"
							<cfif prc.settings.securityHeaders.hostHeaderValidation.enabled>
								checked="checked"
							</cfif>
							role="switch"
							id="flexSwitchCheckDefault">
					</div>

					<div class="fw-semibold">Allowed Hosts: </div>
					<code>#prc.settings.securityHeaders.hostHeaderValidation.allowedHosts#</code>
				</span>
			</li>

			<li class="list-group-item d-flex justify-content-between align-items-center">
				<span class="w-50">
					<div class="text-secondary fw-semibold">
						IP Address Validation
					</div>
					<small class="text-muted">
						This header validates the incoming ipd or forwarded ipd against a valid list of allowed ips.
						If not, the firewall will block the request with a <code>403 : Not Authorized</code> response.
					</small>
				</span>
				<span class="flex-grow-1 ms-2">
					<div
						class="form-check form-switch"
						data-bs-placement="left"
						data-bs-toggle="tooltip"
						data-bs-title="#prc.settings.securityHeaders.ipValidation.enabled ? 'Enabled' : 'Disabled'#"
					>
						<input
							class="form-check-input opacity-100"
							disabled
							type="checkbox"
							<cfif prc.settings.securityHeaders.ipValidation.enabled>
								checked="checked"
							</cfif>
							role="switch"
							id="flexSwitchCheckDefault">
					</div>

					<div class="fw-semibold">Allowed IPs: </div>
					<code>#prc.settings.securityHeaders.ipValidation.allowedIPs#</code>
				</span>
			</li>

			<li class="list-group-item d-flex justify-content-between align-items-center">
				<span class="w-50 me-2">
					<div class="text-secondary fw-semibold">SSL Redirects</div>
					<small class="text-muted">
						Detect if the incoming requests are NON-SSL and if enabled, redirect with SSL
					</small>
				</span>
				<span class="flex-grow-1 ms-2">
					<div
						class="form-check form-switch"
						data-bs-placement="left"
						data-bs-toggle="tooltip"
						data-bs-title="#prc.settings.securityHeaders.secureSSLRedirects.enabled ? 'Yes' : 'No'#"
					>
						<input
							class="form-check-input opacity-100"
							disabled
							type="checkbox"
							<cfif prc.settings.securityHeaders.secureSSLRedirects.enabled>
								checked="checked"
							</cfif>
							role="switch"
							id="flexSwitchCheckDefault">
					</div>
				</span>
			</li>
		</ul>

		<h2>Security Response Headers</h2>

		<ul class="list-group mt-3 mb-5">

			<li class="list-group-item d-flex justify-content-between align-items-center">
				<span class="w-50">
					<div class="text-secondary fw-semibold">
						Content Security Policy
						<a href="https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP" target="_blank">
							<i class="bi bi-info-circle-fill"></i>
						</a>
					</div>
					<small class="text-muted">
						Content Security Policy (CSP) is an added layer of security that helps to detect and mitigate certain types of attacks,
						including Cross-Site Scripting (XSS) and data injection attacks.
					</small>
				</span>
				<span class="flex-grow-1 ms-2">
					<div
						class="form-check form-switch"
						data-bs-placement="left"
						data-bs-toggle="tooltip"
						data-bs-title="#prc.settings.securityHeaders.contentSecurityPolicy.enabled ? 'Enabled' : 'Disabled'#"
					>
						<input
							class="form-check-input opacity-100"
							disabled
							type="checkbox"
							<cfif prc.settings.securityHeaders.contentSecurityPolicy.enabled>
								checked="checked"
							</cfif>
							role="switch"
							id="flexSwitchCheckDefault">
					</div>

					<code>#prc.settings.securityHeaders.contentSecurityPolicy.policy#</code>
				</span>
			</li>

			<li class="list-group-item d-flex justify-content-between align-items-center">
				<span class="w-50">
					<div class="text-secondary fw-semibold">
						Content Type Options
						<a href="https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Content-Type-Options" target="_blank">
							<i class="bi bi-info-circle-fill"></i>
						</a>
					</div>
					<small class="text-muted">
						This response HTTP header is a marker used by the server to indicate that the MIME types advertised in
						the Content-Type headers should be followed and not be changed.
					</small>
				</span>
				<span class="flex-grow-1 ms-2">
					<div
						class="form-check form-switch"
						data-bs-placement="left"
						data-bs-toggle="tooltip"
						data-bs-title="#prc.settings.securityHeaders.contentTypeOptions.enabled ? 'Enabled' : 'Disabled'#"
					>
						<input
							class="form-check-input opacity-100"
							disabled
							type="checkbox"
							<cfif prc.settings.securityHeaders.contentTypeOptions.enabled>
								checked="checked"
							</cfif>
							role="switch"
							id="flexSwitchCheckDefault">
					</div>

					<code>X-Content-Type-Options: nosniff</code>
				</span>
			</li>

			<li class="list-group-item d-flex justify-content-between align-items-center">
				<span class="w-50">
					<div class="text-secondary fw-semibold">
						Custom Headers
					</div>
					<small class="text-muted">
						You can add any customer headers into each request according to your security needs.
					</small>
				</span>
				<span class="flex-grow-1 ms-2">
					<code>#serializeJSON( prc.settings.securityHeaders.customHeaders )#</code>
				</span>
			</li>

			<li class="list-group-item d-flex justify-content-between align-items-center">
				<span class="w-50">
					<div class="text-secondary fw-semibold">
						Frame Options
						<a href="https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Frame-Options" target="_blank">
							<i class="bi bi-info-circle-fill"></i>
						</a>
					</div>
					<small class="text-muted">
						Disable Click jacking, or i-frame busting.
					</small>
				</span>
				<span class="flex-grow-1 ms-2">
					<div
						class="form-check form-switch"
						data-bs-placement="left"
						data-bs-toggle="tooltip"
						data-bs-title="#prc.settings.securityHeaders.frameOptions.enabled ? 'Enabled' : 'Disabled'#"
					>
						<input
							class="form-check-input opacity-100"
							disabled
							type="checkbox"
							<cfif prc.settings.securityHeaders.frameOptions.enabled>
								checked="checked"
							</cfif>
							role="switch"
							id="flexSwitchCheckDefault">
					</div>

					<code>X-frame-options: #prc.settings.securityHeaders.frameOptions.value#</code>
				</span>
			</li>

			<li class="list-group-item d-flex justify-content-between align-items-center">
				<span class="w-50">
					<div class="text-secondary fw-semibold">
						HTTP Strict Transport Security (HSTS)
						<a href="https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Strict-Transport-Security" target="_blank">
							<i class="bi bi-info-circle-fill"></i>
						</a>
					</div>
					<small class="text-muted">
						This header informs browsers that the site should only be accessed using HTTPS, and that any future attempts to access it
						using HTTP should automatically be converted to HTTPS.
					</small>
					<ul class="mt-3">
						<li>Max-Age : <code>#prc.settings.securityHeaders.hsts[ 'max-age' ]#</code></li>
						<li>Preload : <code>#prc.settings.securityHeaders.hsts.preLoad#</code></li>
						<li>Include Sub Domains : <code>#prc.settings.securityHeaders.hsts.includeSubDomains#</code></li>
					</ul>
				</span>
				<span class="flex-grow-1 ms-2">
					<div
						class="form-check form-switch"
						data-bs-placement="left"
						data-bs-toggle="tooltip"
						data-bs-title="#prc.settings.securityHeaders.hsts.enabled ? 'Enabled' : 'Disabled'#"
					>
						<input
							class="form-check-input opacity-100"
							disabled
							type="checkbox"
							<cfif prc.settings.securityHeaders.hsts.enabled>
								checked="checked"
							</cfif>
							role="switch"
							id="flexSwitchCheckDefault">
					</div>
				</span>
			</li>

			<li class="list-group-item d-flex justify-content-between align-items-center">
				<span class="w-50">
					<div class="text-secondary fw-semibold">
						Referrer Policy
						<a href="https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Referrer-Policy" target="_blank">
							<i class="bi bi-info-circle-fill"></i>
						</a>
					</div>
					<small class="text-muted">
						This header controls how much referrer information (sent with the Referer header)
						should be included with requests. Aside from the HTTP header, you can set this policy in HTML.
					</small>
				</span>
				<span class="flex-grow-1 ms-2">
					<div
						class="form-check form-switch"
						data-bs-placement="left"
						data-bs-toggle="tooltip"
						data-bs-title="#prc.settings.securityHeaders.referrerPolicy.enabled ? 'Enabled' : 'Disabled'#"
					>
						<input
							class="form-check-input opacity-100"
							disabled
							type="checkbox"
							<cfif prc.settings.securityHeaders.referrerPolicy.enabled>
								checked="checked"
							</cfif>
							role="switch"
							id="flexSwitchCheckDefault">
					</div>

					<code>Referrer-Policy: #prc.settings.securityHeaders.referrerPolicy.policy#</code>
				</span>
			</li>

			<li class="list-group-item d-flex justify-content-between align-items-center">
				<span class="w-50">
					<div class="text-secondary fw-semibold">
						XSS Protection
						<a href="https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-XSS-Protection" target="_blank">
							<i class="bi bi-info-circle-fill"></i>
						</a>
					</div>
					<small class="text-muted">
						Some browsers have built in support for filtering out reflected XSS attacks. Not foolproof,
						 but it assists in XSS protection.
					</small>
				</span>
				<span class="flex-grow-1 ms-2">
					<div
						class="form-check form-switch"
						data-bs-placement="left"
						data-bs-toggle="tooltip"
						data-bs-title="#prc.settings.securityHeaders.xssProtection.enabled ? 'Enabled' : 'Disabled'#"
					>
						<input
							class="form-check-input opacity-100"
							disabled
							type="checkbox"
							<cfif prc.settings.securityHeaders.xssProtection.enabled>
								checked="checked"
							</cfif>
							role="switch"
							id="flexSwitchCheckDefault">
					</div>

					<code>X-XSS-Protection: 1; mode=#prc.settings.securityHeaders.xssProtection.mode#</code>
				</span>
			</li>

		</ul>

	</div>
	</cfoutput>
