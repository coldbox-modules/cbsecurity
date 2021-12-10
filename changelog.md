# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

----

## [2.15.0] => 2021-DEC-10

### :rocket: Added

* Pass custom claims from `refreshToken( token, customClaims)` method when refreshing tokens
* Pass in the current jwt payload in to `getJWTCustomClaims( payload )`
* The auto refresh token features now will auto refresh not only on expired tokens, but on invalid and missing tokens as well. Thanks to @elpete

### :bug: Fixed

* Timeout in token storage is now the token timeout

----

## [2.14.0] => 2021-OCT-07

### Added

* `threadsafe` annotation to all models to prevent invalid creations under load, since we don't use circular dependencies.

----

## [2.13.0] => 2021-SEP-02

### Added

* Adobe 2021 Support
* Migration to github actions from travis
* Refresh tokens support
* Refresh token endpoint `/cbsecurity/refreshtToken` for secure refresh token generation
* Manual refresh token method on the `JwtService` : `refreshToken( token )`
* Auto refresh token header interceptions for JWT validators
* Detect on `authenticate()` if the payload is empty and throw the appropriate exceptions
* Added ability for the `authenticate( payload )` to receive a payload to authenticate
* Added ability to recreate the token storage using a `force` argument `getTokenStorage( force = false )`
* Ability for the `parseToken()` to choose to store and authenticate or just parse

### Changed

* The `IAuthUser` no longer requires the `isLoggedIn()` method. This is now fully optional.

### Fixed

* Unique `jti` could have collisions if tokens created at the same time, add randomness to it
* `TokenExpirationException` not relaeyed from the base jwt library
* If `variables.settings.jwt.tokenStorage.enabled` is disabled all invalidations failed, make sure if the storage is disabled to not throw storage exceptions.

----

## [2.12.0] => 2021-MAR-29

### Added

* More and more apps will need real ip's from request, so expose it via the `CBSecurity` model service as : `getRealIp()`

### Fixed

* When using `getHTTPREquestData()` send `false` so we DON'T retrieve the http body when we just need the headers
* More updates to `getRealIp()` when dealing with lists

----

## [2.11.1] => 2021-MAR-10

### Fixed

* Fix `getRealIP()` to only return originating user's source IP, if the forwarded ip is a list

----

## [2.11.0] => 2021-MAR-10

### Added

* Add a `secureSameUser` method to throw when passed a different user #29 (https://github.com/coldbox-modules/cbsecurity/pull/29)

----

## [2.10.0] => 2021-FEB-12

### Added

* Moved the registration of the validator from the `configure()` to the `afterAspectsLoad()` interception point to allow for modules to declare the validator if needed.
* Moved handler bean to `afterAspectsLoad()` to allow for module based invalid events to work.

----

## [2.9.0] => 2020-DEC-11

### Fixed

* Fixes a typo in the `cbSecurity_onInvalidAuthorization` interception point declaration. Previously, the typo would prevent ColdBox from allowing the correctly-typed interception point from ever triggering an interception listener.
* The `userValidator()` method has been changed to `roleValidator()`, but the error message was forgotten! So the developer is told they need a `userValidator()` method... because the `userValidator` method is no longer supported. :/

### Added

* The `isLoggedIn()` method now makes sure that a jwt is in place and valid, before determining if you are logged in or not.
* Migrated all automated tests to `focal` and `mysql8` in preparation for latest updates
* Add support for JSON/XML/model rules source when loading rules from modules.  Each module can now load rules not only inline but from the documented external sources.
* Ensure non-configured `rules` default to empty array

----

## [2.8.0] => 2020-NOV-09

### Added

* `parseToken( token )` now accepts a token of your choice to work with in the request or it will continue to discover it if not passed.
* Added new JWT Service method: `invalidateAll()` which invalidates all tokens in the token storage
* Added the new event: `cbSecurity_onJWTInvalidateAllTokens` that fires once all tokens in the storage are cleared
* Added storage of the authenticated user into the `prc` scope when using `attempt()` to be consistent with API calls

### Fixed

* Spelling corrections on the readme
* Added full var scoping for `cbsecurity` in JWTService calls

----

## [2.7.0] => 2020-SEP-14

### Added

* Contributed module rules are now pre-pended instead of appended. (@wpdebruin)


### Fixed

* Not loading rules by source file detection due to invalid setting check
* Don't trigger ColdBox's invalid event looping protection. It also auto-senses between ColdBox 6 and 5 (@homestar9)
* Fixed token scopes according to JWT spec, it is called `scope` and it is a space separated list. This doesn't change the User interface for it. (@wpdebruin)
* Update token storages so no token rejection anymore when storage is not enabled. (@wpdebruin)


----

## [2.6.0] => 2020-JUL-22

### Added

* New build layout based on new module layout
* Auto github publishing release notes
* More formatting goodness and watcher

### Fixed

* JWT Validator now passing `permissions` instead of `roles`
* Token Storage checking was being done even if disabled


----

## [2.5.0] => 2020-APR-03

* `Feature` : Upgraded to `cbAuth` @ 5.x

----

## [2.4.0] => 2020-APR-02

* `Feature` : We now include the `cbcsrf` module to allow for protections of cross site request forgery vectors. Please see all the features included in this module here: https://github.com/coldbox-modules/cbcsrf

----

## [2.3.0] => 2020-MAR-30

* `Feature` Introduction of the cbSecurity model: https://coldbox-security.ortusbooks.com/intro/release-history/whats-new-with-2.3.0
* `Task` : Cfformatting everywhere

----

## [2.2.1] => 2020-FEB-26

* `bug` : `verify` should pass `verify=true` into the jwt library for proper verification

----

## [2.2.0] => 2020-FEB-12

* `Feature` : Migrated from the jwt to the `jwtcfml` (https://forgebox.io/view/jwt-cfml) library to expand encoding/decoding capabilities to support `RS` and `ES` algorithms:
  * HS256
  * HS384
  * HS512
  * RS256
  * RS384
  * RS512
  * ES256
  * ES384
  * ES512
* `Feature` : Added a new convenience method on the JWT Service: `isTokenInStorage( token )` to verify if a token still exists in the token storage
* `Feature` : If no jwt secret is given in the settings, we will dynamically generate one that will last for the duration of the application scope.
* `Feature` : New setting for `jwt` struct: `issuer`, you can now set the issuer of tokens string or if not set, then cbSecurity will use the home page URI as the issuer of authority string.
* `Feature` : All tokens will be validated that the same `iss` (Issuer) has granted the token
* `Improve` : Ability to have defaults for all JWT settings instead of always typing them in the configs
* `Improve` : More cfformating goodness!
* `Bug` : Invalidation of tokens was not happening due to not using the actual key for the storage

----

## [2.1.0] => 2019-OCT-02

* `Feature` : cbauth upgraded to version 4

----

## [2.0.0] => 2019-SEP-25

### New Features

* Adobe 2016,2018 Support
* Settings transferred to ColdBox 4/5 `moduleSettings` approach instead of root approach (See compat section)
* The `rulesModelMethod` now defaults to `getSecurityRules()`
* ColdFusion security validator has an identity now `CFValidator@cbsecurity` instead of always being inline.
* You can now add an `overrideEvent` element to a rule. If that is set, then we will override the incoming event via `event.overrideEvent()` instead of doing a relocation using the `redirect` rule element.
* You can now declare your rules inline in the configuration settings using the `rules` key. This will allow you to build the rules in your config instead of a rule source.
* We now can distinguish between invalid auth and invalid authorizations
* New interception block points `cbSecurity_onInvalidAuthentication`, `cbSecurity_onInvalidAuhtorization`
* You now have a `defaultAuthorizationAction` setting which defaults to `redirect`
* You now have a `invalidAuthenticationEvent` setting that can be used
* You now have a `defaultAuthenticationAction` setting which defaults to `redirect`
* You now have a `invalidAuthorizationEvent` setting that can be used
* If a rule is matched, we will store it in the `prc` as `cbSecurity_matchedRule` so you can see which security rule was used for processing invalid access actions.
* If a rule is matched we will store the validator results in `prc` as `cbSecurity_validatorResults`
* Ability for modules to register cbSecurity rules and setting overrides by registering a `settings.cbSecurity` key.
* Ability for modules to override the `validator` setting. So each module can have their own security validator schema.
* New security rule visualizer for graphically seeing you rules and configuration.  Can be locked down via the `enableSecurityVisualizer` setting. Disabled by default.

```json
// module settings - stored in modules.name.settings
settings = {
	// CB Security Rules to append to global rules
	cbsecurity = {
		// The module invalid authentication event or URI or URL to go if an invalid authentication occurs
		"invalidAuthenticationEvent"	: "",
		// Default Auhtentication Action: override or redirect when a user has not logged in
		"defaultAuthenticationAction"	: "redirect",
		// The module invalid authorization event or URI or URL to go if an invalid authorization occurs
		"invalidAuthorizationEvent"		: "",
		// Default Authorization Action: override or redirect when a user does not have enough permissions to access something
		"defaultAuthorizationAction"	: "redirect",
		// You can define your security rules here or externally via a source
		"rules"							: [
			{
				"secureList" 	: "mod1:home"
			},
			{
				"secureList" 	: "mod1/modOverride",
				"match"			: "url",
				"action"		: "override"
			}
		]
	}
};
```

* Annotation based security for handlers and actions using the `secured` annotation.  Which can be boolean or a list of permissions, roles or whatever you like.
* You can disable annotation based security by using the `handlerAnnotationSecurity` boolean setting.

## Improvements

* SSL Enforcement now cascades according to the following lookup: Global, rule, request
* Interfaces documented for easier extension `interfaces.*`
* Migration to script and code modernization
* New Module Layout
* Secured rules are now logged as `warn()` with the offending Ip address.
* New setting to turn on/off the loading of the security firewall: `autoLoadFirewall`. The interceptor will auto load and be registered as `cbsecurity@global` in WireBox.

### Compat

* Adobe 11 Dropped
* Lucee 4.5 Dropped
* Migrate your root `cbSecurity` settings in your `config/ColdBox.cfc` to inside the `moduleSettings`
* IOC rules support dropped
* OCM rules support dropped
* `validatorModel` dropped in favor of just `validator` to be a WireBox Id
* Removed `preEventSecurity` it was too chatty and almost never used
* The function `userValidator` has been renamed to `ruleValidator` and also added the `annotationValidator` as well.
* `rulesSource` removed you can now use the `rules` setting
  * The `rules` can be: `array, db, model, filepath`
  * If the `filepath` has `json` or `xml` in it, we will use that as the source style
* `rulesFile` removed you can now use the `rules` setting.

## [1.3.0]

* Travis integration
* DocBox updates
* Build process updates

## [1.2.0]

* Updated documentation
* Updated doc references
* New docs build process
* Update root builder dependencies

## [1.1.0]

* Updated documentation
* Ability for interceptor to auto-register via new `cbsecurity` settings in master config.

## [1.0.2]

* Removed `getPlugin()` deprecated calls to new approach.
* https://ortussolutions.atlassian.net/browse/CCM-26 cbsecurity ocm rules not ColdBox 4 compat

## [1.0.1]

* Fixed missing `$throw()` method to native `throw()` method.

## [1.0.0]

* Created first module version
