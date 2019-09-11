# CHANGELOG

## 2.0.0

### Features

* Adobe 2016,2018 Support
* Settings transferred to ColdBox 4/5 `moduleSettings` approach instead of root approach (See compat section)
* The `rulesModelMethod` now defaults to `getSecurityRules()`
* ColdFusion security validator has an identity now `CFValidator@cbsecurity` instead of always being inline.
* You can now add an `overrideEvent` element to a rule. If that is set, then we will override the incoming event via `event.overrideEvent()` instead of doing a relocation using the `redirect` rule element.
* You can now declare your rules inline in the configuration settings using the `rules` key. This will allow you to build the rules in your config instead of a rule source.
* Once a rule is blocked a `cbSecurity_onInvalidAccess` event is announced so you can determine what invalid actions to do.  You can even bypass the default actions of relocations/overrides if needed.

The following are the keys received in this event:
- `ip` 					// The offending IP
- `rule` 				// The broken rule
- `settings`			// All the config settings, just in case
- `processActions:true` // Boolean indicator if the invalid actions should process or not, default is to process actions (true). Turn off to do your thing!

* You now have a `defaultInvalidAction` setting which defaults to `redirect`
* You now have a `invalidAccessRedirect` setting which is a global redirect so you don't have to define the redirect in the rules anymore. If you do, then it uses the most explicit definition first.
* You now have a `invalidAccessOverrideEvent` setting which is a global override so you don't have to define the override in the rules anymore. If you do, then it uses the most explicit definition first.
 
## Improvements

* SSL Enforcement now cascades according to the following lookup: Global, rule, request
* Interfaces documented for easier extension `models.interfaces.*`
* Migration to script and code modernization
* New Module Layout
* Secured rules are now logged as `warn()` with the offending Ip address.
* If the main ColdBox application has settings defined to load cbSecurity the interceptor will auto load and be registered as `cbsecurity@global` in WireBox.

### Compat

* Adobe 11 Dropped
* Lucee 4.5 Dropped
* Migrate your root `cbSecurity` settings in your `config/ColdBox.cfc` to inside the `moduleSettings`
* IOC rules support dropped
* OCM rules support dropped
* `validatorModel` dropped in favor of just `validator` to be a WireBox Id
* Removed `preEventSecurity` it was too chatty and almost never used

### Bugs

* Removed entry point for avoiding adding routes

## 1.3.0

* Travis integration
* DocBox updates
* Build process updates

## 1.2.0

* Updated documentation
* Updated doc references
* New docs build process
* Update root builder dependencies

## 1.1.0

* Updated documentation
* Ability for interceptor to auto-register via new `cbsecurity` settings in master config.

## 1.0.2

* Removed `getPlugin()` deprecated calls to new approach.
* https://ortussolutions.atlassian.net/browse/CCM-26 cbsecurity ocm rules not ColdBox 4 compat 

## 1.0.1

* Fixed missing `$throw()` method to native `throw()` method.

## 1.0.0

* Created first module version
