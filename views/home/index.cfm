<cfoutput>
<h1 class="display-4">ColdBox Security Visualizer</h1>

<p class="lead">Security rules are traversed for matching in specific order.</p>

<ul class="nav nav-tabs" id="myTab" role="tablist">
	<li class="nav-item">
		<a class="nav-link active" id="rules-tab" data-toggle="tab" href="##rules" role="tab" aria-controls="rules" aria-selected="true">Rules</a>
	</li>
	<li class="nav-item">
		<a class="nav-link" id="settings-tab" data-toggle="tab" href="##settings" role="tab" aria-controls="settings" aria-selected="false">Settings</a>
	</li>
</ul>

<div class="tab-content" id="myTabContent">
	<div class="tab-pane fade show active" id="rules" role="tabpanel" aria-labelledby="rules-tab">
		#renderView(
			view = "home/rules",
			module = "cbsecurity"
		)#
	</div>
	<div class="tab-pane fade" id="settings" role="tabpanel" aria-labelledby="settings-tab">
		#renderView(
			view = "home/settings",
			module = "cbsecurity"
		)#
	</div>
</div>

</cfoutput>
