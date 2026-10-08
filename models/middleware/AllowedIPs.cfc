/**
 * Copyright since 2016 by Ortus Solutions, Corp
 * www.ortussolutions.com
 * ---
 * Route middleware that only lets listed IPs through (IPv4, IPv6 and CIDR ranges). Everyone else gets a 403.
 *
 * <pre>
 * route( "/admin" ).middleware( "AllowedIPs@cbsecurity" ).meta( { allowedIps : "10.0.0.0/8,203.0.113.7" } ).to( "admin.index" )
 * </pre>
 *
 * The list is required. A route without one throws `cbsecurity.MiddlewareMisconfigured` instead of silently
 * allowing or blocking everyone. Behind a proxy, set `middleware.trustedProxies`.
 */
component extends="BaseMiddleware" {

	boolean function preProcess( required event, rc, prc ){
		var routeMeta = getRouteMeta( arguments.event );
		var allowed   = toArray( routeMeta.allowedIps ?: "" );

		if ( !allowed.len() ) {
			misconfigured( "AllowedIPs requires the route meta key [allowedIps]" );
		}

		if ( ipMatchesAny( getClientIP( arguments.event ), allowed ) ) {
			return false;
		}

		return deny(
			arguments.event,
			403,
			"Your IP address is not allowed"
		);
	}

}
