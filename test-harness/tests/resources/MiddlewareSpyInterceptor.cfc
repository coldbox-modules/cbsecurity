/**
 * Records the invalid authentication interception data for the middleware specs
 */
component {

	function cbSecurity_onInvalidAuthentication( event, data ){
		request.mwSpy = {
			"source" : arguments.data.annotationType,
			"type"   : arguments.data.validatorResults.type
		};
	}

}
