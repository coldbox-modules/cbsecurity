<cfoutput>
<div x-data="{
	}"
>

	<h2 class="mb-4">Firewall Activity</h2>

	<!--- If not enabled, how to enable them --->
	<cfif !prc.settings.firewall.logs.enabled>
		<div class="alert alert-warning">
			<i class="bi bi-exclamation-triangle-fill"></i> Your firewall logs are disabled!
		</div>
		<p>
			To enable logging make sure you setup the following settings:
			<pre>
				<code>
	"firewall" : {
		"logs" : {
			"enabled"    : true,
			"dsn"        : "", // leave empty to use the application's default datasource
			"schema"     : "",
			"table"      : "cbsecurity_logs",
			"autoCreate" : true
		}
	}
				</code>
			</pre>
		</p>
	<cfelse>

		<!--- Report Row 1 --->
		<div class="row">
			<div class="col-12">
				<div class="row">

					<!--- Card 1 --->
					<div class="col-md-3">

						<div class="card border-1">
							<div class="card-body bg-dark">
								<div class="row">
									<div class="col d-flex justify-content-between">

										<div class="text-light">
											<!-- Title -->
											<h5 class="d-flex align-items-center mb-2">
												<span class="text-uppercase fw-semibold">
													Events
												</span>
												<span
													class="ms-2 fs-6"
													data-bs-toggle="tooltip"
													data-bs-title="The total number of times the firewall intercepted requests"
												>
													<i class="bi bi-info-circle-fill"></i>
												</span>
											</h5>

											<!-- Subtitle -->
											<h2 class="mb-0">
												#numberFormat( prc.logCounts )#
											</h2>

											<p class="fs-6 mb-0 mt-1">
												Total Firewall Activity
											</p>
										</div>

										<span class="text-primary fs-2">
											<i class="bi bi-activity"></i>
										</span>
									</div>
								</div> <!-- / .row -->
							</div>
						</div>

					</div>

					<!--- Card 2 --->
					<div class="col-md-3">
						<!-- Card -->
						<div class="card border-1">
							<div class="card-body">
								<div class="row">
									<div class="col d-flex justify-content-between">

										<div>
											<!-- Title -->
											<h5 class="d-flex align-items-center mb-2">
												<span class="text-uppercase text-muted fw-semibold">
													Blocks
												</span>
												<span
													class="ms-2 text-muted fs-6"
													data-bs-toggle="tooltip"
													data-bs-title="The total number of 401 blocks"
												>
													<i class="bi bi-info-circle-fill"></i>
												</span>
											</h5>

											<!-- Subtitle -->
											<h2 class="mb-0">
												#numberFormat( prc.actionsReport[ "block" ] )#
											</h2>

											<!-- Comment -->
											<p class="fs-6 text-muted mb-0 mt-1">
												#numberFormat( ( prc.actionsReport[ "block" ] / prc.logCounts ) * 100, "00" )#%
											</p>
										</div>

										<span class="text-danger fs-2">
											<i class="bi bi-shield-x"></i>
										</span>
									</div>
								</div> <!-- / .row -->
							</div>
						</div>
					</div>

					<!--- Card3 --->
					<div class="col-md-3">
						<!-- Card -->
						<div class="card border-1">
							<div class="card-body">
								<div class="row">
									<div class="col d-flex justify-content-between">

										<div>
											<!-- Title -->
											<h5 class="d-flex align-items-center mb-2">
												<span class="text-uppercase text-muted fw-semibold">
													Overrides
												</span>
												<span
													class="ms-2 text-muted fs-6"
													data-bs-toggle="tooltip"
													data-bs-title="The total event overrides executed"
												>
													<i class="bi bi-info-circle-fill"></i>
												</span>
											</h5>

											<!-- Subtitle -->
											<h2 class="mb-0">
												#numberFormat( prc.actionsReport[ "override" ] )#
											</h2>

											<!-- Comment -->
											<p class="fs-6 text-muted mb-0 mt-1">
												#numberFormat( ( prc.actionsReport[ "override" ] / prc.logCounts ) * 100, "00" )#%
											</p>
										</div>

										<span class="text-warning fs-2">
											<i class="bi bi-bezier2"></i>
										</span>
									</div>
								</div> <!-- / .row -->
							</div>
						</div>
					</div>

					<!--- Card 4 --->
					<div class="col-md-3">
						<!-- Card -->
						<div class="card border-1">
							<div class="card-body">
								<div class="row">
									<div class="col d-flex justify-content-between">

										<div>
											<!-- Title -->
											<h5 class="d-flex align-items-center mb-2">
												<span class="text-uppercase text-muted fw-semibold">
													Redirects
												</span>
												<span
													class="ms-2 text-muted fs-6"
													data-bs-toggle="tooltip"
													data-bs-title="The total URL Redirects"
												>
													<i class="bi bi-info-circle-fill"></i>
												</span>
											</h5>

											<!-- Subtitle -->
											<h2 class="mb-0">
												#numberFormat( prc.actionsReport[ "redirect" ] )#
											</h2>

											<!-- Comment -->
											<p class="fs-6 text-muted mb-0 mt-1">
												#numberFormat( ( prc.actionsReport[ "redirect" ] / prc.logCounts ) * 100, "00" )#%
											</p>
										</div>

										<span class="text-warning fs-2">
											<i class="bi bi-send-exclamation"></i>
										</span>
									</div>
								</div> <!-- / .row -->
							</div>
						</div>
					</div>


				</div> <!-- / .row -->
			</div>
		</div>
		<!--- End Report Row 1 --->

		<h3 class="my-4">Block Types</h3>

		<div class="row">
			<div class="col-12">
				<div class="row">

					<!--- Card 1 --->
					<div class="col-md-6">

						<div class="card border-1">
							<div class="card-body">
								<div class="row">
									<div class="col d-flex justify-content-between">

										<div>
											<!-- Title -->
											<h5 class="d-flex align-items-center mb-2">
												<span class="text-uppercase text-muted fw-semibold">
													Authentication Blocks
												</span>
											</h5>

											<!-- Subtitle -->
											<h2 class="mb-0">
												#numberFormat( prc.blockTypesReport[ "authentication" ] )#
											</h2>

											<p class="fs-6 text-muted mb-0 mt-1">
												#numberFormat( ( prc.blockTypesReport[ "authentication" ] / prc.logCounts ) * 100, "00" )#%
											</p>
										</div>

										<span class="text-danger fs-2">
											<i class="bi bi-person-circle"></i>
										</span>
									</div>
								</div> <!-- / .row -->
							</div>
						</div>

					</div>

					<!--- Card 2 --->
					<div class="col-md-6">
						<!-- Card -->
						<div class="card border-1">
							<div class="card-body">
								<div class="row">
									<div class="col d-flex justify-content-between">

										<div>
											<!-- Title -->
											<h5 class="d-flex align-items-center mb-2">
												<span class="text-uppercase text-muted fw-semibold">
													Authorization Blocks
												</span>
											</h5>

											<!-- Subtitle -->
											<h2 class="mb-0">
												#numberFormat( prc.blockTypesReport[ "authorization" ] )#
											</h2>

											<!-- Comment -->
											<p class="fs-6 text-muted mb-0 mt-1">
												#numberFormat( ( prc.blockTypesReport[ "authorization" ] / prc.logCounts ) * 100, "00" )#%
											</p>

										</div>

										<span class="text-info fs-2">
											<i class="bi bi-shield-lock"></i>
										</span>
									</div>
								</div> <!-- / .row -->
							</div>
						</div>
					</div>
				</div> <!-- / .row -->
			</div>
		</div>

	</cfif>

</div>
</cfoutput>
