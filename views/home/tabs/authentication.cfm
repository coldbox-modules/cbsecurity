<cfoutput>
<div class="m-4">

	<h2>Authentication Settings</h2>

	<ul class="list-group mt-3">
		<li class="list-group-item d-flex justify-content-between align-items-center">
			<span class="fw-semibold w-25 text-secondary">Authentication Provider</span>
			<span class="flex-grow-1">
				<code>#prc.settings.authentication.provider#</code>
			</span>
		</li>

		<li class="list-group-item d-flex justify-content-between align-items-center">
			<span class="fw-semibold w-25 text-secondary">User Service</span>
			<span class="flex-grow-1">
				<code>#prc.settings.authentication.userService#</code>
			</span>
		</li>

		<li class="list-group-item d-flex justify-content-between align-items-center">
			<span class="fw-semibold w-25 text-secondary">PRC User Variable</span>
			<span class="flex-grow-1">
				<code>#prc.settings.authentication.prcUserVariable#</code>
			</span>
		</li>
	</ul>

</div>
</cfoutput>
