/**
 * My Event Handler Hint
 */
component extends="coldbox.system.EventHandler" {

	/**
	 * Index
	 */
	any function index( event, rc, prc ){
		return "secured";
	}

	/**
	 * authenticated
	 */
	function authenticated( event, rc, prc ){
		return "auth";
	}

}
