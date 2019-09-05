<cfscript>
	// Allow unique URL or combination (false)
	setUniqueURLS(false);
	// Auto reload configuration, true in dev makes sense
	//setAutoReload(false);
	// Sets automatic route extension detection and places the extension in the rc.format
	// setExtensionDetection(true)
	// setValidExtensions('xml,json,jsont,rss,html,htm');

	// Base URL
	if( len(getSetting('AppMapping') ) lte 1){
		setBaseURL("http://#cgi.HTTP_HOST#/index.cfm");
	}
	else{
		setBaseURL("http://#cgi.HTTP_HOST#/#getSetting('AppMapping')#/index.cfm");
	}


	// API Routing
	defaultAPIActions = {
		"GET":"index",
		"POST":"add",
		"PUT":"onInvalidHTTPMethod",
		"PATCH":"onInvalidHTTPMethod",
		"DELETE":"onInvalidHTTPMethod"
	};
	defaultEntityActions = {
		"GET":"get",
		"PUT":"update",
		"PATCH":"update",
		"DELETE":"delete"
	};


	/**
	* Users API (v1)
	**/

	//Login
	addRoute(
		pattern='/api/v1/users/login',
		handler='api.v1.Users',
		action={"POST":"login","DELETE":"logout"}
	);

	addRoute(
		pattern='/api/v1/users/:id',
		handler='api.v1.Users',
		action=defaultEntityActions
	);

	addRoute(
		pattern='/api/v1/users',
		handler='api.v1.Users',
		action=defaultAPIActions
	);


	// Your Application Routes
	addRoute(pattern=":handler/:action?");
</cfscript>