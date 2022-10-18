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
				return item.secureList.toLowerCase().includes( this.search ) ||
				item.whiteList.toLowerCase().includes( this.search ) ||
				item.module.toLowerCase().includes( this.search ) ||
				item.redirect.toLowerCase().includes( this.search ) ||
				item.overrideEvent.toLowerCase().includes( this.search );
			} )
		},
		clearSearch(){
			this.search = '';
		}
	}"
>

	<div class="input-group mb-3">
		<input
			type="text"
			name="filter"
			id="filter"
			x-model="search"
			placeholder="Filter Rules"
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

	<table class="table table-condensed table-hover" id="table-rules">
		<thead class="thead-dark">
			<tr>
				<th width="50">order</th>
				<th width="50">match</th>
				<th>secure</th>
				<th>whitelist</th>
				<th>roles</th>
				<th>permissions</th>
				<th>action</th>
				<th>redirect</th>
				<th>override</th>
				<th>ssl</th>
				<th>module</th>
				<th>http methods</th>
				<th>allowed ips</th>
			</tr>
		</thead>

		<tbody>
		<template x-for="(rule, index) in filteredRules">
			<tr class="rules">
				<td x-text="index">
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
							<code>Inherit</code>
						</span>
				</td>
				<td>
					<code x-text="rule.redirect"></code>
				</td>
				<td>
					<code x-text="rule.overrideEvent"></code>
				</td>
				<td>
					<span
						class="badge"
						:class="rule.useSSL ? 'text-bg-danger' : 'text-bg-light'"
						x-text="rule.useSSL"
						></span>
				</td>
				<td>
					<code x-text="rule.module"></code>
				</td>
				<td>
					<code x-text="rule.httpMethods"></code>
				</td>
				<td>
					<code x-text="rule.allowedIps"></code>
				</td>
			</tr>
		</template>
		</tbody>
	</table>
</div>
</cfoutput>
