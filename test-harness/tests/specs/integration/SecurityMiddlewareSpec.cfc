/**
 * Specs for the non authenticating route middleware: EnsureHttps, AllowedIPs, DenyIPs, ApiKey, Honeypot,
 * VerifyCsrf, Throttle and Signed, plus the RateLimiter, UrlSigner and signed URL mixins.
 *
 * Paths that depend on request headers or the connection address are tested by calling the middleware directly with
 * a mocked event. Everything else goes through real routes.
 */
component extends="coldbox.system.testing.BaseTestCase" appMapping="/root" {

	this.unloadColdbox = false;

	function beforeAll(){
		super.beforeAll();
	}

	function afterAll(){
		super.afterAll();
	}

	function run(){
		// Route specs need ColdBox 8.3+: execute() runs route middleware and groups can carry meta
		var skipRouteSpecs = function(){
			return !routeMiddlewareTestable();
		};

		describe( "cbsecurity route middleware", function(){
			beforeEach( function( currentSpec ){
				setup();
				// Throttle counters live in the default cache
				getWireBox()
					.getInstance( "cachebox" )
					.getCache( "default" )
					.clearAll();
				// The signed URL checks read the URL scope, so start from an empty one (the runner fills it)
				originalUrl = duplicate( url );
				structClear( url );
			} );

			afterEach( function( currentSpec ){
				structClear( url );
				structAppend( url, originalUrl );
			} );

			/************************** IP MATCHING **************************/

			describe( "IP matching", function(){
				beforeEach( function(){
					mw = getInstance( "AllowedIPs@cbsecurity" );
				} );

				it( "matches exact IPv4 addresses", function(){
					expect( mw.ipMatches( "10.1.2.3", "10.1.2.3" ) ).toBeTrue();
					expect( mw.ipMatches( "10.1.2.4", "10.1.2.3" ) ).toBeFalse();
				} );

				it( "matches IPv4 CIDR ranges", function(){
					expect( mw.ipMatches( "10.200.1.1", "10.0.0.0/8" ) ).toBeTrue();
					expect( mw.ipMatches( "11.0.0.1", "10.0.0.0/8" ) ).toBeFalse();
					expect( mw.ipMatches( "192.168.1.77", "192.168.1.64/26" ) ).toBeTrue();
					expect( mw.ipMatches( "192.168.1.128", "192.168.1.64/26" ) ).toBeFalse();
					expect( mw.ipMatches( "8.8.8.8", "0.0.0.0/0" ) ).toBeTrue();
				} );

				it( "matches IPv6 addresses and ranges", function(){
					expect( mw.ipMatches( "::1", "::1" ) ).toBeTrue();
					expect( mw.ipMatches( "2001:db8::5", "2001:db8::/32" ) ).toBeTrue();
					expect( mw.ipMatches( "2001:db9::5", "2001:db8::/32" ) ).toBeFalse();
				} );

				it( "never matches across IP families", function(){
					expect( mw.ipMatches( "127.0.0.1", "::1" ) ).toBeFalse();
					expect( mw.ipMatches( "::1", "127.0.0.1/8" ) ).toBeFalse();
				} );

				it( "does not match invalid input", function(){
					expect( mw.ipMatches( "not-an-ip", "10.0.0.0/8" ) ).toBeFalse();
					expect( mw.ipMatches( "10.0.0.1", "10.0.0.0/99" ) ).toBeFalse();
				} );

				it( "matches any rule in a list", function(){
					expect( mw.ipMatchesAny( "10.0.0.9", [ "203.0.113.0/24", "10.0.0.0/8" ] ) ).toBeTrue();
					expect( mw.ipMatchesAny( "10.0.0.9", [] ) ).toBeFalse();
				} );
			} );

			describe( "client IP and trusted proxies", function(){
				beforeEach( function(){
					mw       = prepareMock( getInstance( "AllowedIPs@cbsecurity" ) );
					ev       = prepareMock( getRequestContext() );
					settings = mw.getSettings();
					original = duplicate( settings.middleware.trustedProxies );
				} );

				afterEach( function(){
					settings.middleware.trustedProxies = original;
				} );

				it( "uses the connection address when no proxies are trusted", function(){
					mw.$( "getRemoteAddr", "198.51.100.9" );
					ev.$( "getHTTPHeader", "1.2.3.4" );
					expect( mw.getClientIP( ev ) ).toBe( "198.51.100.9" );
				} );

				it( "ignores X-Forwarded-For when the connection is not a trusted proxy", function(){
					settings.middleware.trustedProxies = [ "10.0.0.0/8" ];
					mw.$( "getRemoteAddr", "198.51.100.9" );
					ev.$( "getHTTPHeader", "1.2.3.4" );
					expect( mw.getClientIP( ev ) ).toBe( "198.51.100.9" );
				} );

				it( "reads X-Forwarded-For from a trusted proxy, skipping trusted hops from the right", function(){
					settings.middleware.trustedProxies = [ "10.0.0.0/8" ];
					mw.$( "getRemoteAddr", "10.0.0.2" );
					ev.$( "getHTTPHeader", "6.6.6.6, 203.0.113.50, 10.0.0.1" );
					expect( mw.getClientIP( ev ) ).toBe( "203.0.113.50" );
				} );
			} );

			/************************** EnsureHttps **************************/

			describe( "EnsureHttps@cbsecurity", function(){
				beforeEach( function(){
					mw = getInstance( "EnsureHttps@cbsecurity" );
					ev = prepareMock( getRequestContext() );
				} );

				it( "lets HTTPS requests through", function(){
					ev.$( "isSSL", true );
					expect( mw.preProcess( ev ) ).toBeFalse();
				} );

				it( "redirects GET requests to HTTPS with a 301", function(){
					ev.$( "isSSL", false )
						.$( "getHTTPMethod", "GET" )
						.$( "getUrl", "http://example.com/mw/https" );
					ev.$( "relocate" );
					expect( mw.preProcess( ev ) ).toBeTrue();
					var call = ev.$callLog().relocate[ 1 ];
					expect( call.URL ).toBe( "https://example.com/mw/https" );
					expect( call.statusCode ).toBe( 301 );
				} );

				it( "denies non GET requests with a 403 instead of redirecting", function(){
					ev.$( "isSSL", false ).$( "getHTTPMethod", "POST" );
					ev.$( "relocate" );
					expect( mw.preProcess( ev ) ).toBeTrue();
					expect( ev.$callLog().relocate ).toBeEmpty();
					expect( ev.getRenderData().statusCode ).toBe( 403 );
				} );

				it( "denies instead of redirecting when the route turns redirects off", function(){
					ev.$( "isSSL", false ).$( "getHTTPMethod", "GET" );
					ev.setPrivateValue( "currentRouteMeta", { redirectToHttps : false } );
					ev.$( "relocate" );
					expect( mw.preProcess( ev ) ).toBeTrue();
					expect( ev.$callLog().relocate ).toBeEmpty();
					expect( ev.getRenderData().statusCode ).toBe( 403 );
				} );
			} );

			/************************** AllowedIPs / DenyIPs **************************/

			describe(
				title = "AllowedIPs@cbsecurity and DenyIPs@cbsecurity",
				skip  = skipRouteSpecs,
				body  = function(){
					it( "allows a listed address", function(){
						var event = get( route = "/mw/ip/allowed", renderResults = true );
						expect( event.getRenderedContent() ).toBe( "mw ok" );
					} );

					it( "denies an address that is not listed", function(){
						var event = get( route = "/mw/ip/notAllowed", renderResults = true );
						expect( event.getRenderData().statusCode ).toBe( 403 );
						expect( event.getRenderedContent() ).notToBe( "mw ok" );
					} );

					it( "throws when AllowedIPs has no list", function(){
						expect( function(){
							get( route = "/mw/ip/unconfigured" );
						} ).toThrow( "cbsecurity.MiddlewareMisconfigured" );
					} );

					it( "blocks a denied address", function(){
						var event = get( route = "/mw/ip/denied", renderResults = true );
						expect( event.getRenderData().statusCode ).toBe( 403 );
					} );

					it( "lets other addresses through DenyIPs", function(){
						var event = get( route = "/mw/ip/notDenied", renderResults = true );
						expect( event.getRenderedContent() ).toBe( "mw ok" );
					} );

					it( "uses a spoofed client address only from trusted proxies", function(){
						var mw = prepareMock( getInstance( "DenyIPs@cbsecurity" ) );
						var ev = prepareMock( getRequestContext() );
						ev.setPrivateValue( "currentRouteMeta", { denyIps : "203.0.113.50" } );
						mw.$( "getRemoteAddr", "198.51.100.9" );
						ev.$( "getHTTPHeader", "203.0.113.50" );
						// Not a trusted proxy, so the header is ignored and the request passes
						expect( mw.preProcess( ev ) ).toBeFalse();
					} );
				}
			);

			/************************** ApiKey **************************/

			describe( "ApiKey@cbsecurity", function(){
				describe(
					title = "routes",
					skip  = skipRouteSpecs,
					body  = function(){
						it( "reads the key from the apiKey request key by default", function(){
							var event = get(
								route         = "/mw/apikey",
								params        = { apiKey : "key-two" },
								renderResults = true
							);
							expect( event.getRenderedContent() ).toBe( "mw ok" );
						} );

						it( "denies a missing key with a 401", function(){
							var event = get( route = "/mw/apikey", renderResults = true );
							expect( event.getRenderData().statusCode ).toBe( 401 );
						} );

						it( "denies a wrong key with a 401", function(){
							var event = get(
								route         = "/mw/apikey",
								params        = { apiKey : "key-three" },
								renderResults = true
							);
							expect( event.getRenderData().statusCode ).toBe( 401 );
						} );

						it( "supports a custom request key from the route meta", function(){
							var event = get(
								route         = "/mw/apikey/custom",
								params        = { token : "key-one" },
								renderResults = true
							);
							expect( event.getRenderedContent() ).toBe( "mw ok" );
						} );

						it( "ignores the default request key when the route names another", function(){
							var event = get( route = "/mw/apikey/custom", params = { apiKey : "key-one" } );
							expect( event.getRenderData().statusCode ).toBe( 401 );
						} );

						it( "throws when no keys or validator are configured", function(){
							expect( function(){
								get( route = "/mw/apikey/unconfigured" );
							} ).toThrow( "cbsecurity.MiddlewareMisconfigured" );
						} );
					}
				);

				describe( "headers", function(){
					beforeEach( function(){
						mw = prepareMock( getInstance( "ApiKey@cbsecurity" ) );
						ev = prepareMock( getRequestContext() );
						ev.setPrivateValue( "currentRouteMeta", { apiKeys : "abc123" } );
					} );

					it( "reads x-api-key by default", function(){
						ev.$( "getHTTPHeader", "abc123" );
						expect( mw.preProcess( ev ) ).toBeFalse();
					} );

					it( "denies a wrong header value", function(){
						ev.$( "getHTTPHeader", "zzz" );
						expect( mw.preProcess( ev ) ).toBeTrue();
						expect( ev.getRenderData().statusCode ).toBe( 401 );
					} );

					it( "asks for the configured header", function(){
						ev.setPrivateValue( "currentRouteMeta", { apiKeys : "abc123", apiKeyHeader : "x-token" } );
						ev.$( "getHTTPHeader", "abc123" );
						mw.preProcess( ev );
						expect( ev.$callLog().getHTTPHeader[ 1 ][ 1 ] ).toBe( "x-token" );
					} );

					it( "asks for x-api-key when nothing is configured", function(){
						ev.$( "getHTTPHeader", "abc123" );
						mw.preProcess( ev );
						expect( ev.$callLog().getHTTPHeader[ 1 ][ 1 ] ).toBe( "x-api-key" );
					} );

					it( "falls back to a validator service", function(){
						var validator = createStub().$( "isValidKey", true );
						var wb        = createStub().$( "getInstance", validator );
						mw.$property( "wirebox", "variables", wb );
						ev.setPrivateValue( "currentRouteMeta", {} );
						mw.getSettings().middleware.apiKey.validator = "FakeKeyValidator";
						try {
							ev.$( "getHTTPHeader", "from-db" );
							expect( mw.preProcess( ev ) ).toBeFalse();
							expect( validator.$callLog().isValidKey[ 1 ][ 1 ] ).toBe( "from-db" );
						} finally {
							mw.getSettings().middleware.apiKey.validator = "";
						}
					} );
				} );
			} );

			/************************** Honeypot **************************/

			describe(
				title = "Honeypot@cbsecurity",
				skip  = skipRouteSpecs,
				body  = function(){
					it( "lets requests with an empty trap through", function(){
						var event = post(
							route         = "/mw/honeypot",
							params        = { name : "Ana" },
							renderResults = true
						);
						expect( event.getRenderedContent() ).toBe( "mw ok" );
					} );

					it( "ignores a whitespace only trap", function(){
						var event = post(
							route         = "/mw/honeypot",
							params        = { website_url : "  " },
							renderResults = true
						);
						expect( event.getRenderedContent() ).toBe( "mw ok" );
					} );

					it( "answers a filled trap with a silent 200 and skips the handler", function(){
						var event = post(
							route         = "/mw/honeypot",
							params        = { website_url : "http://spam.example" },
							renderResults = true
						);
						expect( event.getRenderData().statusCode ).toBe( 200 );
						expect( event.getRenderedContent() ).notToBe( "mw ok" );
					} );

					it( "answers a filled trap with a 422 when not silent, using the configured field", function(){
						var event = post(
							route         = "/mw/honeypot/loud",
							params        = { nickname : "bot" },
							renderResults = true
						);
						expect( event.getRenderData().statusCode ).toBe( 422 );
					} );

					it( "ignores the default field when the route names another", function(){
						var ok = post(
							route         = "/mw/honeypot/loud",
							params        = { website_url : "x" },
							renderResults = true
						);
						expect( ok.getRenderedContent() ).toBe( "mw ok" );
					} );
				}
			);

			/************************** VerifyCsrf **************************/

			describe(
				title = "VerifyCsrf@cbsecurity",
				skip  = skipRouteSpecs,
				body  = function(){
					it( "does not check safe methods", function(){
						var event = get( route = "/mw/csrf", renderResults = true );
						expect( event.getRenderedContent() ).toBe( "mw ok" );
					} );

					it( "denies an unsafe request without a token", function(){
						var event = post( route = "/mw/csrf", renderResults = true );
						expect( event.getRenderData().statusCode ).toBe( 403 );
					} );

					it( "denies an unsafe request with a bad token", function(){
						var event = post(
							route         = "/mw/csrf",
							params        = { csrf : "nope" },
							renderResults = true
						);
						expect( event.getRenderData().statusCode ).toBe( 403 );
					} );

					it( "allows an unsafe request with a valid token", function(){
						var token = getInstance( "@cbcsrf" ).generate();
						var event = post(
							route         = "/mw/csrf",
							params        = { csrf : token },
							renderResults = true
						);
						expect( event.getRenderedContent() ).toBe( "mw ok" );
					} );

					it( "accepts the token in the x-csrf-token header", function(){
						var token = getInstance( "@cbcsrf" ).generate();
						var mw    = getInstance( "VerifyCsrf@cbsecurity" );
						var ev    = prepareMock( getRequestContext() );
						ev.$( "getHTTPMethod", "DELETE" ).$( "getHTTPHeader", token );
						expect( mw.preProcess( ev ) ).toBeFalse();
					} );
				}
			);

			/************************** RateLimiter **************************/

			describe( "RateLimiter@cbsecurity", function(){
				beforeEach( function(){
					limiter = getInstance( "RateLimiter@cbsecurity" );
				} );

				it( "starts at zero", function(){
					expect( limiter.attempts( "k1" ) ).toBe( 0 );
					expect( limiter.availableIn( "k1" ) ).toBe( 0 );
					expect( limiter.tooManyAttempts( "k1", 3 ) ).toBeFalse();
				} );

				it( "counts hits and reports remaining attempts", function(){
					expect( limiter.hit( "k2", 60 ) ).toBe( 1 );
					expect( limiter.hit( "k2", 60 ) ).toBe( 2 );
					expect( limiter.attempts( "k2" ) ).toBe( 2 );
					expect( limiter.remaining( "k2", 5 ) ).toBe( 3 );
					expect( limiter.remaining( "k2", 1 ) ).toBe( 0 );
				} );

				it( "reports too many attempts at the limit", function(){
					limiter.hit( "k3", 60 );
					limiter.hit( "k3", 60 );
					expect( limiter.tooManyAttempts( "k3", 3 ) ).toBeFalse();
					limiter.hit( "k3", 60 );
					expect( limiter.tooManyAttempts( "k3", 3 ) ).toBeTrue();
				} );

				it( "reports when the window resets", function(){
					limiter.hit( "k4", 60 );
					expect( limiter.availableIn( "k4" ) ).toBeBetween( 1, 60 );
				} );

				it( "opens a new window after the old one ends", function(){
					limiter.hit( "k5", 1 );
					sleep( 2100 );
					expect( limiter.attempts( "k5" ) ).toBe( 0 );
					expect( limiter.hit( "k5", 1 ) ).toBe( 1 );
				} );

				it( "clears a key", function(){
					limiter.hit( "k6", 60 );
					limiter.clear( "k6" );
					expect( limiter.attempts( "k6" ) ).toBe( 0 );
				} );

				it( "keeps keys apart", function(){
					limiter.hit( "k7a", 60 );
					expect( limiter.attempts( "k7b" ) ).toBe( 0 );
				} );

				it( "uses the named cache provider", function(){
					expect( function(){
						limiter.hit( "k8", 60, "doesNotExist" );
					} ).toThrow();
				} );
			} );

			/************************** Throttle **************************/

			describe(
				title = "Throttle@cbsecurity",
				skip  = skipRouteSpecs,
				body  = function(){
					it( "allows requests up to the named limiter's limit and then returns 429", function(){
						expect( get( route = "/mw/throttle/named", renderResults = true ).getRenderedContent() ).toBe(
							"mw ok"
						);
						expect( get( route = "/mw/throttle/named", renderResults = true ).getRenderedContent() ).toBe(
							"mw ok"
						);
						var blocked = get( route = "/mw/throttle/named", renderResults = true );
						expect( blocked.getRenderData().statusCode ).toBe( 429 );
					} );

					it( "supports inline limits on the route", function(){
						expect( get( route = "/mw/throttle/inline", renderResults = true ).getRenderedContent() ).toBe(
							"mw ok"
						);
						expect( get( route = "/mw/throttle/inline" ).getRenderData().statusCode ).toBe( 429 );
					} );

					it( "counts each route separately", function(){
						get( route = "/mw/throttle/inline" );
						expect( get( route = "/mw/throttle/inline" ).getRenderData().statusCode ).toBe( 429 );
						expect( get( route = "/mw/throttle/named", renderResults = true ).getRenderedContent() ).toBe(
							"mw ok"
						);
					} );

					it( "throws for an unknown limiter name", function(){
						expect( function(){
							get( route = "/mw/throttle/unknown" );
						} ).toThrow( "cbsecurity.MiddlewareMisconfigured" );
					} );

					it( "uses the cacheProvider from the limiter and fails loudly if it does not exist", function(){
						expect( function(){
							get( route = "/mw/throttle/badCache" );
						} ).toThrow();
					} );

					it( "sets rate limit headers on allowed requests and Retry-After on denied ones", function(){
						var mw = getInstance( "Throttle@cbsecurity" );
						var ev = prepareMock( getRequestContext() );
						ev.$( "setHTTPHeader", ev );
						ev.setPrivateValue(
							"currentRouteMeta",
							{ throttle : { maxAttempts : 1, decaySeconds : 60 } }
						);
						ev.setPrivateValue( "currentRoute", "header-spec" );

						expect( mw.preProcess( ev ) ).toBeFalse();
						var names = ev
							.$callLog()
							.setHTTPHeader
							.map( function( c ){
								return c.name;
							} );
						expect( names ).toInclude( "X-RateLimit-Limit" );
						expect( names ).toInclude( "X-RateLimit-Remaining" );

						expect( mw.preProcess( ev ) ).toBeTrue();
						var denied = ev
							.$callLog()
							.setHTTPHeader
							.map( function( c ){
								return c.name;
							} );
						expect( denied ).toInclude( "Retry-After" );
					} );

					it( "defaults to the default cache and counts users separately when by is user", function(){
						var mw = prepareMock( getInstance( "Throttle@cbsecurity" ) );
						var ev = prepareMock( getRequestContext() );
						ev.$( "setHTTPHeader", ev );
						ev.setPrivateValue( "currentRouteMeta", { throttle : { maxAttempts : 1, by : "user" } } );
						ev.setPrivateValue( "currentRoute", "by-user-spec" );
						var cbs = createStub().$( "isLoggedIn", true );
						cbs.$( "getUser", createStub().$( "getId", 1 ) );
						mw.$property( "cbSecurity", "variables", cbs );
						expect( mw.preProcess( ev ) ).toBeFalse();
						expect( mw.preProcess( ev ) ).toBeTrue();

						cbs.$( "getUser", createStub().$( "getId", 2 ) );
						expect( mw.preProcess( ev ) ).toBeFalse();
					} );
				}
			);

			/************************** UrlSigner **************************/

			describe( "UrlSigner@cbsecurity", function(){
				beforeEach( function(){
					signer = getInstance( "UrlSigner@cbsecurity" );
				} );

				it( "signs and validates a URL", function(){
					var link = signer.sign( "https://example.com/invoices/42?ref=a" );
					expect( link ).toInclude( "signature=" );
					expect( signer.isValid( link ) ).toBeTrue();
					expect( signer.check( link ) ).toBe( "valid" );
				} );

				it( "reports a URL without a signature as missing", function(){
					expect( signer.check( "https://example.com/invoices/42" ) ).toBe( "missing" );
				} );

				it( "detects a changed path", function(){
					var link = signer.sign( "https://example.com/invoices/42" );
					expect( signer.check( replace( link, "/42", "/43" ) ) ).toBe( "invalid" );
				} );

				it( "detects a changed, added or removed parameter", function(){
					var link = signer.sign( "https://example.com/d?ref=a" );
					expect( signer.check( replace( link, "ref=a", "ref=b" ) ) ).toBe( "invalid" );
					expect( signer.check( link & "&admin=1" ) ).toBe( "invalid" );
					expect( signer.check( replace( link, "ref=a&", "" ) ) ).toBe( "invalid" );
				} );

				it( "detects a tampered signature", function(){
					var link = signer.sign( "https://example.com/d" );
					expect( signer.check( left( link, len( link ) - 1 ) & "0" ) ).toBe( "invalid" );
				} );

				it( "ignores the scheme, host and parameter order", function(){
					var link      = signer.sign( "https://internal.local/d?a=1&b=2" );
					var signature = reMatch( "signature=[a-f0-9]+", link )[ 1 ];
					expect( signer.isValid( "http://public.example.com/d?b=2&a=1&" & signature ) ).toBeTrue();
				} );

				it( "expires links", function(){
					var link = signer.sign( "https://example.com/d", 1 );
					expect( signer.check( link ) ).toBe( "valid" );
					sleep( 2100 );
					expect( signer.check( link ) ).toBe( "expired" );
				} );

				it( "cannot have its expiration extended", function(){
					var link  = signer.sign( "https://example.com/d", 1 );
					var other = reReplace( link, "expires=\d+", "expires=99999999999" );
					expect( signer.check( other ) ).toBe( "invalid" );
				} );

				it( "replaces an existing signature when signing again", function(){
					var once  = signer.sign( "https://example.com/d?ref=a" );
					var twice = signer.sign( once );
					expect( listLen( twice, "&" ) ).toBe( 2 );
					expect( signer.isValid( twice ) ).toBeTrue();
				} );

				it( "encodes parameter values", function(){
					var link = signer.sign( "https://example.com/d?note=a%20b%26c" );
					expect( signer.isValid( link ) ).toBeTrue();
				} );

				it( "refuses to sign without a secret", function(){
					var original = signer.getSettings().signedUrls.secret;
					signer.getSettings().signedUrls.secret = "";
					try {
						expect( function(){
							signer.sign( "https://example.com/d" );
						} ).toThrow( "cbsecurity.SigningSecretMissing" );
					} finally {
						signer.getSettings().signedUrls.secret = original;
					}
				} );

				it( "rejects a signature made with a different secret", function(){
					var link     = signer.sign( "https://example.com/d" );
					var original = signer.getSettings().signedUrls.secret;
					signer.getSettings().signedUrls.secret = "another-secret";
					try {
						expect( signer.check( link ) ).toBe( "invalid" );
					} finally {
						signer.getSettings().signedUrls.secret = original;
					}
				} );
			} );

			/************************** Signed middleware + mixins **************************/

			describe(
				title = "Signed@cbsecurity and the signed URL mixins",
				skip  = skipRouteSpecs,
				body  = function(){
					it( "denies an unsigned request with a 403", function(){
						var event = get( route = "/mw/signed/42", renderResults = true );
						expect( event.getRenderData().statusCode ).toBe( 403 );
						expect( event.getPrivateValue( "cbSecurity_signatureStatus" ) ).toBe( "missing" );
					} );

					it( "allows a request for a link made with the signer", function(){
						var link = getInstance( "UrlSigner@cbsecurity" ).sign(
							getRequestContext().route( "mw.signed", { id : 42 } ),
							60
						);
						applyQuery( link );
						var event = get( route = "/mw/signed/42", renderResults = true );
						expect( event.getRenderedContent() ).toBe( "mw ok" );
					} );

					it( "denies a request when the route param was changed", function(){
						var link = getInstance( "UrlSigner@cbsecurity" ).sign(
							getRequestContext().route( "mw.signed", { id : 42 } ),
							60
						);
						applyQuery( link );
						var event = get( route = "/mw/signed/43", renderResults = true );
						expect( event.getRenderData().statusCode ).toBe( 403 );
						expect( event.getPrivateValue( "cbSecurity_signatureStatus" ) ).toBe( "invalid" );
					} );

					it( "denies an expired link and says why", function(){
						var link = getInstance( "UrlSigner@cbsecurity" ).sign(
							getRequestContext().route( "mw.signed", { id : 42 } ),
							1
						);
						applyQuery( link );
						sleep( 2100 );
						var event = get( route = "/mw/signed/42", renderResults = true );
						expect( event.getRenderData().statusCode ).toBe( 403 );
						expect( event.getPrivateValue( "cbSecurity_signatureStatus" ) ).toBe( "expired" );
					} );

					it( "signedRoute() fills route params, puts the rest in the query string and signs", function(){
						var event = get(
							route         = "/mw/link",
							params        = { kind : "route" },
							renderResults = true
						);
						var link = event.getRenderedContent();
						expect( reFindNoCase( "/mw/signed/7/?\?", link ) ).toBeGT( 0 );
						expect( reFindNoCase( "ref=a(%20|\+)b", link ) ).toBeGT( 0 );
						expect( link ).toInclude( "expires=" );
						expect( getInstance( "UrlSigner@cbsecurity" ).isValid( link ) ).toBeTrue();
					} );

					it( "signedUrl() builds a real query string and signs", function(){
						var event = get(
							route         = "/mw/link",
							params        = { kind : "url" },
							renderResults = true
						);
						var link = event.getRenderedContent();
						expect( reFindNoCase( "/mw/signed/9/?\?", link ) ).toBeGT( 0 );
						expect( reFindNoCase( "ref=x", link ) ).toBeGT( 0 );
						expect( getInstance( "UrlSigner@cbsecurity" ).isValid( link ) ).toBeTrue();
					} );

					it( "hasValidSignature() reflects the current request", function(){
						expect( get( route = "/mw/hasSignature", renderResults = true ).getRenderedContent() ).toBe( "no" );
					} );
				}
			);
		} );
	}

	/**
	 * Put a signed link's query string in the URL scope, which is where the middleware reads it
	 */
	private function applyQuery( required string link ){
		listToArray( listRest( arguments.link, "?" ), "&" ).each( function( pair ){
			url[ urlDecode( listFirst( pair, "=" ) ) ] = urlDecode( listRest( pair, "=" ) );
		} );
	}

	/**
	 * Detects if the installed ColdBox can test route middleware: groups carry meta and execute() runs route middleware.
	 */
	private boolean function routeMiddlewareTestable(){
		return (
			fileRead( expandPath( "/coldbox/system/web/routing/Router.cfc" ) ).findNoCase( "groupMetaStack" ) > 0
			&&
			fileRead( expandPath( "/coldbox/system/testing/BaseTestCase.cfc" ) ).findNoCase( "runRouteMiddleware" ) > 0
		);
	}

}
