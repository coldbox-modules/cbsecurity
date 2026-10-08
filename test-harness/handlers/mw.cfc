/**
 * Handler used by the route middleware specs
 */
component {

	function index( event, rc, prc ){
		return "mw ok";
	}

	// Exercises the signedRoute() and signedUrl() mixins
	function link( event, rc, prc ){
		return rc.kind == "route" ? signedRoute( "mw.signed", { id : 7, ref : "a b" }, 60 ) : signedUrl(
			"/mw/signed/9",
			{ ref : "x" }
		);
	}

	// Exercises the hasValidSignature() mixin
	function hasSignature( event, rc, prc ){
		return hasValidSignature() ? "yes" : "no";
	}

}
