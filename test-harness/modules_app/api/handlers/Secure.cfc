/**
 * Secured handler
 */
component extends="coldbox.system.EventHandler"{

	/**
	 * Index
	 */
	any function index( event, rc, prc ){
		return {
			"error" 	: false,
			"data" 		: [ "secured", "data" ],
			"messages" 	: ""
		};
	}

}
