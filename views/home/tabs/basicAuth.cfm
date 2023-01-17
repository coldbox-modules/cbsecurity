<cfoutput>
<div x-data="{
		users : #forAttribute( getInstance( "BasicAuthUserService@cbsecurity" ).getUsers() )#,
		search : '',
		get filteredUsers(){
			if( this.search === '' ){
				return this.users;
			}
			return this.users.filter( (item) => {
				this.search = this.search.toLowerCase();
				return item.username.toLowerCase().includes( this.search );
			} )
		},
		clearSearch(){
			this.search = '';
		}
	}"
>

	<h2>Basic Auth</h2>
	<p>
		Basic auth allows you to challenge users with Browser based
		<a href="https://en.wikipedia.org/wiki/Basic_access_authentication" target="_blank">Basic Authentication</a>.  Not the
		most secure, but it's efficient and quick to use for small security concerns.
	</p>
	<p>
		In order to use basic auth you will have to make sure you use the <code>BasicAuthValidator@cbsecurity</code> as your validator of choice.
		It will connect to <code>cbAuth</code> and use it's configured user's class as well.  This means you can use the basic authentication
		validator with any authentication and/or user system.  However, you can also create a user storage system by leveraging the
		<code>basicAuth.users</code> structure in your configuration and register a secure user and permission based system.
	</p>

	<h3 class="my-2">Settings</h3>

	<ul class="list-group mt-3 mb-3">
		<li class="list-group-item d-flex justify-content-between align-items-center">
			<span class="w-50 me-2">
				<div class="text-secondary fw-semibold">Hashing Algorithm</div>
				<small class="text-muted">
					This is the hashing algorithm used for the passwords of the basic auth user storage (Optional)
				</small>
			</span>
			<span class="flex-grow-1">
				<code>#prc.settings.basicAuth.hashAlgorithm#</code>
			</span>
		</li>

		<li class="list-group-item d-flex justify-content-between align-items-center">
			<span class="w-50 me-2">
				<div class="text-secondary fw-semibold">Hashing Iterations</div>
				<small class="text-muted">
					Iterates the number of times the hash is computed to create a more computationally intensive hash.
				</small>
			</span>
			<span class="flex-grow-1">
				<code>#prc.settings.basicAuth.hashIterations#</code>
			</span>
		</li>

	</ul>

	<h3 class="my-2">Users</h3>

	<div class="input-group mb-3">
		<input
			type="text"
			name="filter"
			id="filter"
			x-model="search"
			placeholder="Filter Users"
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

	<div x-show="filteredUsers.length == 0" class="alert alert-warning">
		No users matched
	</div>

	<table class="table table-condensed table-hover" id="table-rules">
		<thead class="thead-dark">
			<tr>
				<th>username</th>
				<th>roles</th>
				<th>permissions</th>
			</tr>
		</thead>

		<tbody>
		<template x-for="(user, index) in filteredUsers">
			<tr>
				<td>
					<code x-text="user.username"></code>
				</td>
				<td>
					<code x-text="user.roles"></code>
				</td>
				<td>
					<span x-text="user.permissions"></span>
				</td>
			</tr>
		</template>
		</tbody>
	</table>

</div>
</cfoutput>
