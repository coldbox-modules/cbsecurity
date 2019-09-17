<cfoutput>
<div class="form-group">
	<input type="text" name="filter" id="filter" placeholder="Filter Rules" autofocus class="form-control">
</div>

<table class="table table-striped table-condensed table-hover" id="table-rules">
	<thead class="thead-dark">
		<tr>
			<th width="50">order</th>
			<th width="50">match</th>
			<th>securelist</th>
			<th>whitelist</th>
			<th>roles</th>
			<th>permissions</th>
			<th>redirect</th>
			<th>override</th>
			<th>useSSL</th>
			<th>action</th>
			<th>module</th>
			<th width="150" class="text-center">actions</th>
		</tr>
	</thead>

	<tbody>
	<cfset index = 1>
	<cfloop array="#prc.properties.rules#" index="thisRule">
		<cfset thisRule.id = hash( thisRule.toString() )>
		<tr class="rules">
			<td>
				#index++#
			</td>
			<td class="text-center">
				<span class="badge #( thisRule.match == "event" ? "badge-primary" : "badge-warning" )#">
				#thisRule.match#
				</span>
			</td>
			<td>
				#thisRule.securelist#
			</td>
			<td>
				#thisRule.whitelist#
			</td>
			<td>
				#thisRule.roles#
			</td>
			<td>
				#thisRule.permissions#
			</td>
			<td>
				#thisRule.redirect#
			</td>
			<td>
				#thisRule.overrideEvent#
			</td>
			<td>
				<span class="badge #(thisRule.useSSL ? "badge-success" : "badge-secondary" )#">
					#thisRule.useSSL#
				</span>
			</td>
			<td>
				<cfif len( thisRule.action )>
					<cfif thisRule.action == "override">
						<span class="badge badge-primary">override</span>
					<cfelse>
						<span class="badge badge-danger">redirect</span>
					</cfif>
				<cfelse>
					<span class="badge badge-secondary">default</span>
				</cfif>
			</td>
			<td>
				#thisRule.module#
			</td>
			<td class="text-center">
				<button class="btn btn-danger btn-sm" onclick="$( '##debug-#thisRule.id#' ).toggle()">Dump</button>
			</td>
		</tr>

		<!-- Debug Span -->
		<tr class="table-danger" id="debug-#thisRule.id#" style="display:none">
			<td colspan="7">
				<button class="float-right btn btn-danger btn-sm" onclick="$( '##debug-#thisRule.id#' ).toggle()">Close</button>
				<h3>Rule Dump</h3>
				<cfdump var="#thisRule#">
			</td>
		</tr>

	</cfloop>
	</tbody>
</table>
</cfoutput>