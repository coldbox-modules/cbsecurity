component {

	property name="jwt" inject="provider:JWTService@jwt";
	property name="bcrypt" inject="@BCrypt";

	variables.secretKey = "cbsecurity-test";

	/**
	 * index
	 */
	function index( event, rc, prc ){
		return "public";
	}

	/**
	 * pass
	 */
	function pass( event, rc, prc ){
		return variables.bcrypt.hashPassword( "test" );
	}

	/**
	 * gen
	 */
	function gen( event, rc, prc ){
		var start = now();
		return jwt.encode(
			{
				"iss" : event.buildLink(),
				"iat" : toEpoch( start ),
				"sub" : 0,
				"exp" : toEpoch( dateAdd( "n", 60, start ) ),
				"jti" : hash( start & 0 )
			},
			variables.secretKey
		);
	}

	function toEpoch( required target ){
		return dateDiff( "s", dateConvert( "utc2local", "1970-01-01T00:00:00Z" ), arguments.target );
	}

	function fromEpoch( required target ){
		return dateAdd( "s", arguments.target, dateConvert( "utc2local", "1970-01-01T00:00:00Z" ) );
	}

}
