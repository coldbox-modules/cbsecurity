/**
* My Event Handler Hint
*/
component extends="coldbox.system.EventHandler"{

	/**
	* Index
	*/
	any function index( event, rc, prc ){
		return "secured";
	}

	/**
	* auth
	*/
	function auth( event, rc, prc ){
		return "auth";
	}

}
