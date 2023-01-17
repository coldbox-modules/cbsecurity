/**
 * Copyright since 2016 by Ortus Solutions, Corp
 * www.ortussolutions.com
 * ---
 * Security Headers interceptor
 * This interceptor provides security headers according to the configuration used by the config
 * This applies globally to all responses in an application.
 */
component extends="coldbox.system.Interceptor" {

	/*********************************************************************************************/
	/** DI **/
	/*********************************************************************************************/

	property name="settings"   inject="coldbox:moduleSettings:cbsecurity";
	property name="cbSecurity" inject="cbSecurity@cbSecurity";
	property name="DBLogger"   inject="DBLogger@cbSecurity";

	// Static Defaults Config
	variables.DEFAULT_SETTINGS = {
		// If you trust the upstream then we will check the upstream first for specific headers
		"trustUpstream"         : false,
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
		// The X-Content-Type-Options response HTTP header is a marker used by the server to indicate that the MIME types advertised in
		// the Content-Type headers should be followed and not be changed => X-Content-Type-Options: nosniff
		// https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Content-Type-Options
		"contentTypeOptions" : { "enabled" : true },
		"customHeaders"      : {
			 // Name : value pairs as you see fit.
		},
		// Disable Click jacking: X-Frame-Options: DENY OR SAMEORIGIN
		// https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Frame-Options
		"frameOptions" : { "enabled" : true, "value" : "SAMEORIGIN" },
		// HTTP Strict Transport Security (HSTS)
		// The HTTP Strict-Transport-Security response header (often abbreviated as HSTS)
		// informs browsers that the site should only be accessed using HTTPS, and that any future attempts to access it
		// using HTTP should automatically be converted to HTTPS.
		// https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Strict-Transport-Security,
		"hsts"         : {
			"enabled"           : true,
			// The time, in seconds, that the browser should remember that a site is only to be accessed using HTTPS, 1 year is the default
			"max-age"           : "31536000",
			// See Preloading Strict Transport Security for details. Not part of the specification.
			"preload"           : false,
			// If this optional parameter is specified, this rule applies to all of the site's subdomains as well.
			"includeSubDomains" : false
		},
		// Validates the host or x-forwarded-host to an allowed list of valid hosts
		"hostHeaderValidation" : {
			"enabled"      : false,
			// Allowed hosts list
			"allowedHosts" : ""
		},
		// Validates the ip address of the incoming request
		"ipValidation" : {
			"enabled"    : false,
			// Allowed IP list
			"allowedIPs" : ""
		},
		// The Referrer-Policy HTTP header controls how much referrer information (sent with the Referer header) should be included with requests.
		// Aside from the HTTP header, you can set this policy in HTML.
		// https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Referrer-Policy
		"referrerPolicy"     : { "enabled" : true, "policy" : "same-origin" },
		// Detect if the incoming requests are NON-SSL and if enabled, redirect with SSL
		"secureSSLRedirects" : { "enabled" : false },
		// Some browsers have built in support for filtering out reflected XSS attacks. Not foolproof, but it assists in XSS protection.
		// https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-XSS-Protection,
		// X-XSS-Protection: 1; mode=block
		"xssProtection"      : { "enabled" : true, "mode" : "block" }
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
	 * Process early warning security headers
	 */
	function preProcess( event, interceptData, rc, prc ){
		// Secure SSL Redirects
		if ( variables.settings.securityHeaders.secureSSLRedirects.enabled && !arguments.event.isSSL() ) {
			// Debug
			if ( log.canDebug() ) {
				log.debug( "Non-SSL URI detected (#event.getFullUrl()#), redirecting in ssl" );
			}
			variables.dbLogger.log(
				action   : "redirect",
				blockType: "NON-SSL",
				ip       : variables.cbSecurity.getRealIp(),
				host     : variables.cbSecurity.getRealHost(),
				userId   : variables.cbSecurity.isLoggedIn() ? variables.cbSecurity.getUser().getId() : ""
			);
			relocate( url: arguments.event.getFullUrl(), ssl: true );
			return;
		}

		// Host Header Validation
		if (
			variables.settings.securityHeaders.hostHeaderValidation.enabled &&
			len( variables.settings.securityHeaders.hostHeaderValidation.allowedHosts ) &&
			variables.settings.securityHeaders.hostHeaderValidation.allowedHosts != "*"
		) {
			var incomingHost = variables.cbSecurity.getRealHost(
				trustUpstream = variables.settings.securityHeaders.trustUpstream
			);

			if (
				!listFindNoCase(
					variables.settings.securityHeaders.hostHeaderValidation.allowedHosts,
					incomingHost
				)
			) {
				// Debug
				if ( log.canDebug() ) {
					log.debug(
						"Host header validation block. Incoming host (#incomingHost#) is not valid.",
						"Valid hosts are #variables.settings.securityHeaders.hostHeaderValidation.allowedHosts#"
					);
				}

				variables.dbLogger.log(
					action   : "block",
					blockType: "INVALID-HOST",
					ip       : variables.cbSecurity.getRealIp(),
					host     : variables.cbSecurity.getRealHost(),
					userId   : variables.cbSecurity.isLoggedIn() ? variables.cbSecurity.getUser().getId() : ""
				);

				// Announce
				announce(
					"cbSecurity_onFirewallBlock",
					{
						type         : "hostheader",
						config       : variables.settings.securityHeaders.hostHeaderValidation,
						incomingHost : incomingHost
					}
				);

				// block
				event
					.noExecution()
					.renderData(
						data       = "<strong>Invalid Host</strong>",
						statusCode = "403",
						statusText = "Invalid host"
					);
			}
		}

		// IP Header Validation
		if (
			variables.settings.securityHeaders.ipValidation.enabled &&
			len( variables.settings.securityHeaders.ipValidation.allowedIPs ) &&
			variables.settings.securityHeaders.ipValidation.allowedIPs != "*"
		) {
			var incomingIP = variables.cbSecurity.getRealIP(
				trustUpstream = variables.settings.securityHeaders.trustUpstream
			);

			if ( !listFindNoCase( variables.settings.securityHeaders.ipValidation.allowedIPs, incomingIP ) ) {
				// Debug
				if ( log.canDebug() ) {
					log.debug(
						"IP validation block. Incoming ip (#incomingIP#) is not valid.",
						"Valid ips are #variables.settings.securityHeaders.ipValidation.allowedIPs#"
					);
				}

				variables.dbLogger.log(
					action   : "block",
					blockType: "INVALID-IP",
					ip       : variables.cbSecurity.getRealIp(),
					host     : variables.cbSecurity.getRealHost(),
					userId   : variables.cbSecurity.isLoggedIn() ? variables.cbSecurity.getUser().getId() : ""
				);

				// Announce
				announce(
					"cbSecurity_onFirewallBlock",
					{
						type       : "ipvalidation",
						config     : variables.settings.securityHeaders.ipValidation,
						incomingIP : incomingIP
					}
				);

				// block
				event
					.noExecution()
					.renderData(
						data       = "<strong>Invalid IP</strong>",
						statusCode = "403",
						statusText = "Invalid IP"
					);
			}
		}
	}

	/**
	 * Process all output security headers
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
