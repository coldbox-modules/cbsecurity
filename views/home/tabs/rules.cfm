<cfoutput>
<div x-data="{
		rules : #forAttribute( prc.settings.firewall.rules.inline )#,
		search : '',
		get filteredRules(){
			if( this.search === '' ){
				return this.rules;
			}
			return this.rules.filter( (item) => {
				this.search = this.search.toLowerCase();
				return new RegExp( item.secureList ).exec( this.search ) !== null ? true : false;
			} )
		},
		clearSearch(){
			this.search = '';
		}
	}"
>

	<h2>Firewall Rules</h2>
	<p>
		Here are the global and module rules you have defined in your application in the order of discovery and execution.
		You can use the input box to run the rule simulator which tries to match the <code>secure expression</code> to the incoming
		URI or event string.
	</p>

	<div class="input-group mb-3">
		<input
			type="text"
			name="filter"
			id="filter"
			x-model="search"
			placeholder="Enter a URI or event to simulate"
			autofocus
			class="form-control"
		>
		<button
			@click="clearSearch"
			class="btn btn-outline-secondary"
			type="button"
			:disabled="!search.length"
			id="button-addon2">Clear</button>
	</div>

	<div x-show="filteredRules.length == 0" class="alert alert-warning">
		No rules matched
	</div>

	<div class="table-responsive">
		<table class="table table-sm table-hover" id="table-rules">
			<thead class="table-dark">
				<tr>
					<th width="50" class="d-none d-sm-none d-md-none d-lg-table-cell">order</th>
					<th width="50">match</th>
					<th>secure</th>
					<th>whitelist</th>
					<th>roles</th>
					<th>permissions</th>
					<th>action</th>
					<th class="d-none d-sm-none d-md-none d-lg-table-cell">redirect</th>
					<th class="d-none d-sm-none d-md-none d-lg-table-cell">override</th>
					<th class="d-none d-sm-none d-md-none d-lg-table-cell">ssl</th>
					<th class="d-none d-sm-none d-md-none d-lg-table-cell">module</th>
					<th class="d-none d-sm-none d-md-none d-lg-table-cell">http methods</th>
					<th class="d-none d-sm-none d-md-none d-lg-table-cell">allowed ips</th>
				</tr>
			</thead>

			<tbody class="table-group-divider">
			<template x-for="(rule, index) in filteredRules">
				<tr class="rules">
					<td x-text="index" class="d-none d-sm-none d-md-none d-lg-table-cell">
					</td>
					<td class="text-center">
						<span
							class="badge"
							:class="rule.match == 'event' ? 'text-bg-primary' : 'text-bg-info'"
							x-text="rule.match"
						>
						</span>
					</td>
					<td>
						<code x-text="rule.secureList"></code>
					</td>
					<td>
						<code x-text="rule.whiteList"></code>
					</td>
					<td>
						<span x-text="rule.roles"></span>
					</td>
					<td>
						<span x-text="rule.permissions"></span>
					</td>
					<td>
						<span
							class="badge"
							:class="{
								'text-bg-primary' : rule.action == 'override',
								'text-bg-danger' : rule.action == 'block',
								'text-bg-info' : rule.action == 'redirect'
							}"
							x-text="rule.action"
							></span>
							<span
								class="badge text-bg-light"
								x-show="rule.action.length == 0"
							>
								<code>inherit</code>
							</span>
					</td>
					<td class="d-none d-sm-none d-md-none d-lg-table-cell">
						<code x-text="rule.redirect"></code>
					</td>
					<td class="d-none d-sm-none d-md-none d-lg-table-cell">
						<code x-text="rule.overrideEvent"></code>
					</td>
					<td class="d-none d-sm-none d-md-none d-lg-table-cell">
						<span
							class="badge"
							:class="rule.useSSL ? 'text-bg-danger' : 'text-bg-light'"
							x-text="rule.useSSL"
							></span>
					</td>
					<td class="d-none d-sm-none d-md-none d-lg-table-cell">
						<code x-text="rule.module"></code>
					</td>
					<td class="d-none d-sm-none d-md-none d-lg-table-cell">
						<code x-text="rule.httpMethods"></code>
					</td>
					<td class="d-none d-sm-none d-md-none d-lg-table-cell">
						<code x-text="rule.allowedIps"></code>
					</td>
				</tr>
			</template>
			</tbody>
		</table>
	</div>
</div>
</cfoutput>
