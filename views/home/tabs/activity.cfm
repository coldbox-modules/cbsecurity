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

						<div class="card">
							<div class="card-body bg-dark rounded-3">
								<div class="row">
									<div class="col d-flex justify-content-between">

										<div class="text-light">
											<!-- Title -->
											<h5 class="d-flex align-items-center mb-2">
												<span class="text-uppercase text-primary fw-semibold">
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
							<div class="card-body rounded-3">
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
												#numberFormat( prc.actionsReport[ "block" ].total )#
											</h2>
										</div>

										<span class="text-danger fs-2">
											<i class="bi bi-shield-x"></i>
										</span>
									</div>
								</div> <!-- / .row -->

								<div class="row mx-1 mt-2">
									<div
										class="progress"
										style="height: 25px; padding: 0px;"
										data-bs-toggle="tooltip"
										data-bs-title="#numberFormat( prc.actionsReport[ "block" ].percentage, "00" )#%"
									>
										<div
											class="progress-bar bg-info text-dark"
											role="progressbar"
											style="width: #numberFormat( prc.actionsReport[ 'block' ].percentage, '00' )#%;"
											aria-valuenow="#numberFormat( prc.actionsReport[ 'block' ].percentage, '00' )#"
											aria-valuemin="0"
											aria-valuemax="#prc.logCounts#"
											>
											#numberFormat( prc.actionsReport[ "block" ].percentage, "00" )#%
										</div>
									</div>
								</div>
							</div>
						</div>
					</div>

					<!--- Card3 --->
					<div class="col-md-3">
						<!-- Card -->
						<div class="card border-1">
							<div class="card-body rounded-3">
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
												#numberFormat( prc.actionsReport[ "override" ].total )#
											</h2>
										</div>

										<span class="text-warning fs-2">
											<i class="bi bi-bezier2"></i>
										</span>
									</div>
								</div> <!-- / .row -->

								<div class="row mx-1 mt-2">
									<div
										class="progress"
										style="height: 25px; padding: 0px;"
										data-bs-toggle="tooltip"
										data-bs-title="#numberFormat( prc.actionsReport[ "override" ].percentage, "00" )#%"
									>
										<div
											class="progress-bar bg-info text-dark"
											role="progressbar"
											style="width: #numberFormat( prc.actionsReport[ 'override' ].percentage, '00' )#%;"
											aria-valuenow="#numberFormat( prc.actionsReport[ 'override' ].percentage, '00' )#"
											aria-valuemin="0"
											aria-valuemax="#prc.logCounts#"
											>
											#numberFormat( prc.actionsReport[ "override" ].percentage, "00" )#%
										</div>
									</div>
								</div>
							</div>
						</div>
					</div>

					<!--- Card 4 --->
					<div class="col-md-3">
						<!-- Card -->
						<div class="card border-1">
							<div class="card-body rounded-3">
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
												#numberFormat( prc.actionsReport[ "redirect" ].total )#
											</h2>
										</div>

										<span class="text-warning fs-2">
											<i class="bi bi-send-exclamation"></i>
										</span>
									</div>
								</div> <!-- / .row -->

								<div class="row mx-1 mt-2">
									<div
										class="progress"
										style="height: 25px; padding: 0px;"
										data-bs-toggle="tooltip"
										data-bs-title="#numberFormat( prc.actionsReport[ "redirect" ].percentage, "00" )#%"
									>
										<div
											class="progress-bar bg-info text-dark"
											role="progressbar"
											style="width: #numberFormat( prc.actionsReport[ 'redirect' ].percentage, '00' )#%;"
											aria-valuenow="#numberFormat( prc.actionsReport[ 'redirect' ].percentage, '00' )#"
											aria-valuemin="0"
											aria-valuemax="#prc.logCounts#"
											>
											#numberFormat( prc.actionsReport[ "redirect" ].percentage, "00" )#%
										</div>
									</div>
								</div>
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
				<table class="table">
					<thead>
						<th>Type</th>
						<th>Counts</th>
					</thead>
					<tbody>
						<cfloop collection="#prc.blockTypesReport#" item="thisItem">
							<tr>
								<td class="text-uppercase">#thisItem#</td>
								<td>
									<div
										class="progress"
										style="height: 25px"
										data-bs-toggle="tooltip"
										data-bs-title="#numberFormat( prc.blockTypesReport[ thisItem ] )#"
									>
										<div
											class="progress-bar"
											role="progressbar"
											style="width: #numberFormat( ( prc.blockTypesReport[ thisItem ] / prc.logCounts ) * 100 )#%;"
											aria-valuenow="#numberFormat( prc.blockTypesReport[ thisItem ] )#"
											aria-valuemin="0"
											aria-valuemax="#prc.logCounts#"
											>
											#numberFormat( prc.blockTypesReport[ thisItem ] )#
										</div>
									</div>
								</td>
							</tr>
						</cfloop>
					</tbody>
				</table>
			</div>
		</div>

		<h3 class="my-4">Top Events By Source</h3>

		<div class="row">
			<div class="col-md-6">
				<div class="card border-1">
					<div class="card-header fw-semibold">
						Incoming Paths
					</div>
					<div class="card-body rounded-3">
						<div class="row">
							<table class="table table-sm table-hover">
								<thead>
									<th width="50" class="text-center">Total</th>
									<th>Path</th>
								</thead>
								<tbody>
									<cfloop array="#prc.topOffendingPaths#" item="thisItem">
										<tr>
											<td class="text-center">#thisItem.total#</td>
											<td class="text-truncated">
												#thisItem.path#
											</td>
										</tr>
									</cfloop>
								</tbody>
							</table>
						</div> <!-- / .row -->
					</div>
				</div>
			</div>

			<div class="col-md-6">
				<div class="card border-1">
					<div class="card-header fw-semibold">
						IP Addresses
					</div>
					<div class="card-body rounded-3">
						<div class="row">
							<table class="table table-sm table-hover">
								<thead>
									<th class="text-center" width="50">Total</th>
									<th>IP Address</th>
								</thead>
								<tbody>
									<cfloop array="#prc.topOffendingIps#" item="thisItem">
										<tr>
											<td class="text-center">#thisItem.total#</td>
											<td class="text-truncated">
												<a href="https://www.whois.com/whois/#thisItem.ip#" target="_blank">
													<i class="bi bi-box-arrow-up-right"></i> #thisItem.ip#
												</a>
											</td>
										</tr>
									</cfloop>
								</tbody>
							</table>
						</div> <!-- / .row -->
					</div>
				</div>
			</div>
		</div>

		<div class="row mt-4">
			<div class="col-md-6">
				<div class="card border-1">
					<div class="card-header fw-semibold">
						Hosts
					</div>
					<div class="card-body rounded-3">
						<div class="row">
							<table class="table table-sm table-hover">
								<thead>
									<th width="50" class="text-center">Total</th>
									<th>Host</th>
								</thead>
								<tbody>
									<cfloop array="#prc.topOffendingHosts#" item="thisItem">
										<tr>
											<td class="text-center">#thisItem.total#</td>
											<td class="text-truncated">
												#thisItem.host#
											</td>
										</tr>
									</cfloop>
								</tbody>
							</table>
						</div> <!-- / .row -->
					</div>
				</div>
			</div>

			<div class="col-md-6">
				<div class="card border-1">
					<div class="card-header fw-semibold">
						Users
					</div>
					<div class="card-body rounded-3">
						<div class="row">
							<table class="table table-sm table-hover">
								<thead>
									<th class="text-center" width="50">Total</th>
									<th>User Id</th>
								</thead>
								<tbody>
									<cfloop array="#prc.topOffendingUsers#" item="thisItem">
										<tr>
											<td class="text-center">#thisItem.total#</td>
											<td class="text-truncated">
												<cfif !len( thisItem.userId )>
													<span class="text-secondary"><em>none</em></span>
												<cfelse>
													#thisItem.userId#
												</cfif>
											</td>
										</tr>
									</cfloop>
								</tbody>
							</table>
						</div> <!-- / .row -->
					</div>
				</div>
			</div>
		</div>

		<div class="row mt-4">
			<div class="col-md-6">
				<div class="card border-1">
					<div class="card-header fw-semibold">
						User Agents
					</div>
					<div class="card-body rounded-3">
						<div class="row">
							<table class="table table-sm table-hover">
								<thead>
									<th width="50" class="text-center">Total</th>
									<th>User Agent</th>
								</thead>
								<tbody>
									<cfloop array="#prc.topOffendingUserAgents#" item="thisItem">
										<tr>
											<td class="text-center">#thisItem.total#</td>
											<td class="text-truncated">
												#thisItem.userAgent#
											</td>
										</tr>
									</cfloop>
								</tbody>
							</table>
						</div> <!-- / .row -->
					</div>
				</div>
			</div>

			<div class="col-md-6">
				<div class="card border-1">
					<div class="card-header fw-semibold">
						HTTP Methods
					</div>
					<div class="card-body rounded-3">
						<div class="row">
							<table class="table table-sm table-hover">
								<thead>
									<th class="text-center" width="50">Total</th>
									<th>Method</th>
								</thead>
								<tbody>
									<cfloop array="#prc.topOffendingMethods#" item="thisItem">
										<tr>
											<td class="text-center">#thisItem.total#</td>
											<td class="text-truncated">
												#thisItem.httpMethod#
											</td>
										</tr>
									</cfloop>
								</tbody>
							</table>
						</div> <!-- / .row -->
					</div>
				</div>
			</div>
		</div>

		<h3 class="my-4">Latest Activity Log (#prc.logs.recordCount#)</h3>

		<table class="table table-sm table-hover">
			<thead>
				<th width="100">Date</th>
				<th width="85" class="text-center">Action : Type</th>
				<th>Resource</th>
				<th>IP</th>
				<th>User</th>
			</thead>
			<tbody
				x-data="{
					rowId : '',
					show( id ){
						this.rowId = id;
					},
					close( id ){
						this.rowId = '';
					}
				}"
				x-cloak
			>
				<cfloop query="#prc.logs#">
					<tr>
						<td>
							<small class="text-muted">
								#dateTimeFormat( prc.logs.logDate.toString(), "dd MMM, YYYY HH:mm:ss z" )#
							</small>
						</td>
						<td>
							<cfif prc.logs.action eq "block">
								<span class="badge d-block text-bg-danger">
							<cfelseif prc.logs.action eq "override">
								<span class="badge d-block text-bg-primary ">
							<cfelseif prc.logs.action eq "redirect">
								<span class="badge d-block text-bg-info">
							</cfif>
								#prc.logs.action# : #prc.logs.blockType#
							</span>
						</td>
						<td class="text-truncated">

							<cfif len( prc.logs.referer )>
								<span
									data-bs-toggle="tooltip"
									data-bs-title="Referer: #prc.logs.referer#"
								>
									<i class="bi bi-link-45deg"></i>
								</span>

								<i class="bi bi-caret-right-fill"></i>
							<cfelse>
								<span style="margin-left: 31px">&nbsp;</span>
							</cfif>

							<span class="badge bg-primary">
								#prc.logs.httpMethod#
							</span>

							<i class="bi bi-caret-right-fill"></i>
							#prc.logs.host##prc.logs.path#?#prc.logs.queryString#
						</td>
						<td>
							<a href="https://www.whois.com/whois/#prc.logs.ip#" target="_blank">
								<i class="bi bi-box-arrow-up-right"></i> #prc.logs.ip#
							</a>
						</td>
						<td>
							<cfif !len( prc.logs.userId )>
								<span class="text-muted"><em>None</em></span>
							<cfelse>
								#prc.logs.userId#
							</cfif>
						</td>
						<td>
							<button
								class="btn btn-light btn-sm"
								@click="show( '#encodeForJavaScript( prc.logs.id )#' )"
								x-show="rowId != '#encodeForJavaScript( prc.logs.id )#'"
								data-bs-toggle="tooltip"
								data-bs-title="Show Rule"
							>
								<i class="bi bi-chevron-double-down"></i>
							</button>

							<button
								class="btn btn-light btn-sm"
								@click="close( '#encodeForJavaScript( prc.logs.id )#' )"
								x-show="rowId == '#encodeForJavaScript( prc.logs.id )#'"
								data-bs-toggle="tooltip"
								data-bs-title="Close Rule"
							>
								<i class="bi bi-chevron-double-up"></i>
							</button>
						</td>
					</tr>

					<tr
						x-show="rowId == '#encodeForJavaScript( prc.logs.id )#'"
						x-transition.delay.500
					>
						<td colspan="6">
							<cfdump var="#deserializeJSON( prc.logs.securityRule )#">
						</td>
					</tr>
				</cfloop>
			</tbody>
		</table>

	</cfif>
</div>
</cfoutput>
