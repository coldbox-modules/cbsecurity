/**
 * I am a new secured handler
 */
component secured {

	function index( event, rc, prc ){
		return "secured handler";
	}

	/**
	 * secret
	 */
	function secret( event, rc, prc ) secured="awesome-admin"{
		return "Mega secured action!";
	}

}
