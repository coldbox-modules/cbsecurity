component singleton threadsafe extends="AuthValidator" {

	function onDIComplete(){
		variables.log.warn(
			"The CBAuthValidator has been deprecated, please change your references to just `AuthValidator@cbsecurity` "
		);
	}

}
