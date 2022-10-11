/**
 * Security Headers interceptor
 * This interceptor provides security headers according to the configuration used by the config
 * This applies globally to all responses in an application.
 */
component extends="coldbox.system.Interceptor" {

	/*********************************************************************************************/
	/** DI **/
	/*********************************************************************************************/

	property name="settings" inject="coldbox:moduleSettings:cbsecurity";

	// Static Defaults Config
	variables.DEFAULT_SETTINGS = {
		// Master switch for security headers
		"enabled"            : true,
		// Disable Click jacking: X-Frame-Options: DENY OR SAMEORIGIN
		// https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Frame-Options
		"frameOptions"       : { "enabled" : true, "value" : "DENY" },
		// Some browsers have built in support for filtering out reflected XSS attacks. Not foolproof, but it assists in XSS protection.
		// https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-XSS-Protection,
		// X-XSS-Protection: 1; mode=block
		"xssProtection"      : { "enabled" : true, "mode" : "block" },
		// The X-Content-Type-Options response HTTP header is a marker used by the server to indicate that the MIME types advertised in
		// the Content-Type headers should be followed and not be changed => X-Content-Type-Options: nosniff
		// https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Content-Type-Options
		"contentTypeOptions" : { "enabled" : true },
		// The Referrer-Policy HTTP header controls how much referrer information (sent with the Referer header) should be included with requests.
		// Aside from the HTTP header, you can set this policy in HTML.
		// https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Referrer-Policy
		"referrerPolicy"     : { "enabled" : true, "policy" : "same-origin" },
		// HTTP Strict Transport Security (HSTS)
		// The HTTP Strict-Transport-Security response header (often abbreviated as HSTS)
		// informs browsers that the site should only be accessed using HTTPS, and that any future attempts to access it
		// using HTTP should automatically be converted to HTTPS.
		// https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Strict-Transport-Security,
		"hsts"               : {
			"enabled"           : true,
			// The time, in seconds, that the browser should remember that a site is only to be accessed using HTTPS, 1 year is the default
			"max-age"           : "31536000",
			// See Preloading Strict Transport Security for details. Not part of the specification.
			"preload"           : false,
			// If this optional parameter is specified, this rule applies to all of the site's subdomains as well.
			"includeSubDomains" : false
		},
		// Content Security Policy
		// Content Security Policy (CSP) is an added layer of security that helps to detect and mitigate certain types of attacks,
		// including Cross-Site Scripting (XSS) and data injection attacks. These attacks are used for everything from data theft, to
		// site defacement, to malware distribution.
		// https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP
		"contentSecurityPolicy" : {
			// Disabled by defautl as it is totally customizable
			"enabled" : false,
			// The custom policy to use, by default we don't include any
			"policy"  : ""
		},
		"customHeaders" : {
			 // Name : value pairs as you see fit.
		}
	};

	/**
	 * Configure the interceptor
	 */
	void function configure(){
		// Param root configurations
		if ( variables.settings.keyExists( "securityHeaders" ) ) {
			variables.settings.securityHeaders.append( variables.DEFAULT_SETTINGS, false );
		}
		// Inflate nested struct params
		variables.settings.securityHeaders.map( function( key, value ){
			if ( isStruct( arguments.value ) ) {
				arguments.value.append( variables.DEFAULT_SETTINGS[ arguments.key ], false );
			}
			return arguments.value;
		} );
	}

	/**
	 * Process all security headers
	 */
	function postProcess( event, interceptData, rc, prc ){
		if ( variables.settings.securityHeaders.frameOptions.enabled ) {
			event.setHTTPHeader(
				name : "X-Frame-Options",
				value: variables.settings.securityHeaders.frameOptions.value
			);
		}

		if ( variables.settings.securityHeaders.xssProtection.enabled ) {
			var headerValue = "1; ";
			if ( len( variables.settings.securityHeaders.xssProtection.mode ) ) {
				headerValue &= variables.settings.securityHeaders.xssProtection.mode;
			}
			event.setHTTPHeader( name: "X-XSS-Protection", value: headerValue );
		}

		if ( variables.settings.securityHeaders.contentTypeOptions.enabled ) {
			event.setHTTPHeader( name: "X-Content-Type-Options", value: "nosniff" );
		}

		if ( variables.settings.securityHeaders.referrerPolicy.enabled ) {
			event.setHTTPHeader(
				name : "Referrer-Policy",
				value: variables.settings.securityHeaders.referrerPolicy.policy
			);
		}

		if ( variables.settings.securityHeaders.hsts.enabled ) {
			var headerValue = "max-age: #variables.settings.securityHeaders.hsts[ "max-age" ]#;";
			if ( variables.settings.securityHeaders.hsts.includeSubDomains ) {
				headerValue &= " includeSubDomains";
			}
			if ( variables.settings.securityHeaders.hsts.preload ) {
				headerValue &= " preload";
			}
			event.setHTTPHeader( name: "Strict-Transport-Security", value: headerValue );
		}

		if (
			variables.settings.securityHeaders.contentSecurityPolicy.enabled &&
			len( variables.settings.securityHeaders.contentSecurityPolicy.policy )
		) {
			event.setHTTPHeader(
				name : "Content-Security-Policy",
				value: variables.settings.securityHeaders.contentSecurityPolicy.policy
			);
		}

		if ( !variables.settings.securityHeaders.customHeaders.isEmpty() ) {
			variables.settings.securityHeaders.customHeaders.each( function( key, value ){
				event.setHTTPHeader( name: arguments.key, value: arguments.value );
			} );
		}
	}

}
