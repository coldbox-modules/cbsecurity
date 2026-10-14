/**
 * A custom middleware used by the middleware specs: requires the `read` permission and ignores route meta
 */
component extends="cbsecurity.models.middleware.Guard" {

	function init(){
		return super.init( permissions = "read", useMeta = false );
	}

}
