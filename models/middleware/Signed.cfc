/**
 * Copyright since 2016 by Ortus Solutions, Corp
 * www.ortussolutions.com
 * ---
 * Route middleware that only lets requests with a valid signed URL through. Create the links with the `signedRoute()`
 * and `signedUrl()` helpers or `UrlSigner@cbsecurity`.
 *
 * <pre>
 * route( "/invoices/:id/download" ).as( "invoice.download" ).middleware( "Signed@cbsecurity" ).to( "invoices.download" )
 * </pre>
 *
 * A missing, altered or expired signature gets a 403, with the reason (missing, invalid or expired) stored in
 * `prc.cbSecurity_signatureStatus` for your own handling. Requires the `signedUrls.secret` setting.
 */
component extends="BaseMiddleware" {

	property name="urlSigner" inject="UrlSigner@cbsecurity";

	boolean function preProcess( required event, rc, prc ){
		var status = variables.urlSigner.checkRequest( arguments.event );
		if ( status == "valid" ) {
			return false;
		}

		arguments.event.setPrivateValue( "cbSecurity_signatureStatus", status );
		return deny(
			arguments.event,
			403,
			status == "expired" ? "This link has expired" : "This link is not valid"
		);
	}

}
