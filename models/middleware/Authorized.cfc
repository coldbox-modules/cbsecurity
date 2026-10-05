/**
 * Copyright since 2016 by Ortus Solutions, Corp
 * www.ortussolutions.com
 * ---
 * Route middleware: the user must be logged in and satisfy the permissions or roles declared in the route metadata.
 *
 * <pre>
 * route( "/admin" )
 *     .middleware( "Authorized@cbsecurity" )
 *     .meta( { permissions : "ADMIN" } )
 *     .to( "admin.index" )
 *
 * // every permission is required
 * route( "/billing" )
 *     .middleware( "Authorized@cbsecurity" )
 *     .meta( { permissions : "BILLING_READ,BILLING_WRITE", mode : "all" } )
 *     .to( "billing.index" )
 * </pre>
 */
component extends="cbsecurity.models.middleware.Guard" singleton {


}
