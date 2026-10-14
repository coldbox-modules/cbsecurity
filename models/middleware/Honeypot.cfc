/**
 * Copyright since 2016 by Ortus Solutions, Corp
 * www.ortussolutions.com
 * ---
 * Route middleware that catches bots with a hidden form field. People never see the field, bots fill it in.
 *
 * Add the field to your form and hide it with CSS (not `type="hidden"`, bots skip those):
 *
 * <pre>
 * <div style="position:absolute;left:-9999px" aria-hidden="true">
 *     <input type="text" name="website_url" tabindex="-1" autocomplete="off">
 * </div>
 * </pre>
 *
 * Settings: `middleware.honeypot.field` (default `website_url`) and `middleware.honeypot.silent` (default true).
 * Route meta overrides: `honeypotField` and `honeypotSilent`. When silent, bots get a 200 "OK" and the handler never runs.
 * When not silent they get a 422.
 */
component extends="BaseMiddleware" {

	boolean function preProcess( required event, rc, prc ){
		var config = getMiddlewareSettings( "honeypot" );
		var field  = getMetaValue( arguments.event, "honeypotField", config.field );
		var silent = getMetaValue(
			arguments.event,
			"honeypotSilent",
			config.silent
		);

		var value = arguments.event.getValue( field, "" );
		if ( !isSimpleValue( value ) || !len( trim( value ) ) ) {
			return false;
		}

		if ( silent ) {
			arguments.event.renderData( type = "text", data = "OK", statusCode = 200 ).noExecution();
			return true;
		}
		return deny( arguments.event, 422, "Unprocessable request" );
	}

}
