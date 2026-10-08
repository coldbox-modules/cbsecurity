/**
 * Copyright since 2016 by Ortus Solutions, Corp
 * www.ortussolutions.com
 * ---
 * Route middleware that blocks listed IPs (IPv4, IPv6 and CIDR ranges) with a 403. Everyone else passes.
 *
 * <pre>
 * route( "/api" ).middleware( "DenyIPs@cbsecurity" ).meta( { denyIps : "198.51.100.0/24" } ).to( "api.index" )
 * </pre>
 *
 * The list is required. A route without one throws `cbsecurity.MiddlewareMisconfigured`. Behind a proxy, set
 * `middleware.trustedProxies`.
 */
component extends="BaseMiddleware" {

	boolean function preProcess( required event, rc, prc ){
		var routeMeta = getRouteMeta( arguments.event );
		var denied    = toArray( routeMeta.denyIps ?: "" );

		if ( !denied.len() ) {
			misconfigured( "DenyIPs requires the route meta key [denyIps]" );
		}

		if ( ipMatchesAny( getClientIP( arguments.event ), denied ) ) {
			return deny(
				arguments.event,
				403,
				"Your IP address is blocked"
			);
		}

		return false;
	}

}
