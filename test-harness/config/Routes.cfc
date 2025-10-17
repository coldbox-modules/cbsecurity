component{

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
}