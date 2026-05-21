### Quick orientation — cbsecurity (ColdBox module)

This repository is a ColdBox module that provides a request firewall, annotation-driven security, JWT handling, CSRF integration, and security headers.

Keep guidance short and actionable. Prefer small, verifiable edits and reference the real files below.

1) Big picture
- ColdBox module: entrypoint and wiring in `ModuleConfig.cfc` and `models/CBSecurity.cfc`.
- Runtime protection happens in the `cbsecurity.interceptors.Security` interceptor (`interceptors/Security.cfc`) which:
  - loads and normalizes rules via `helpers/RulesLoader` (see `models/util/RulesLoader.cfc`),
  - delegates validation to a Validator (default: `models/validators/AuthValidator.cfc`) via `ruleValidator()` and `annotationValidator()`,
  - processes rule actions (redirect/override/block) and emits interception events (`cbSecurity_onInvalidAuthentication`, etc.).

2) Where to make changes
- Business logic & APIs: `models/` (e.g. `models/jwt/JwtService.cfc`, `models/CBSecurity.cfc`).
- Request enforcement: `interceptors/Security.cfc` (rule matching, IP/HTTP method validation, event overrides).
- Validation strategies: `models/validators/*` — to change how auth/authorization decisions are made.
- Module defaults & wiring: `ModuleConfig.cfc` and `box.json` for dependencies and scripts.

3) Developer workflows (how to run, test, build)
- Install deps and test harness: `box install` at repo root, then `cd test-harness && box install` (or use `box install` from root — `box.json` has `install:dependencies`).
- Run local server for integration/test harness: `box server start server-lucee@5.json` (see `box.json` scripts `start:lucee` / `start:2023`).
- Run tests: this repo uses TestBox. The package `box.json` test runner is configured to `http://localhost:60299/tests/runner.cfm` and `build/Build.cfc` calls `testbox run`. Start the server, then open that URL or run `box testbox run runner=http://localhost:60299/tests/runner.cfm`.
- Useful npm-like tasks are defined in `box.json` under `scripts` (e.g. `box task run taskFile=build/Build.cfc` used by CI). In VSCode use the Task `Run CommandBox Task`.

4) Patterns & conventions to follow
- Validators expose `ruleValidator(rule, controller)` and `annotationValidator(securedValue, controller)`. Return shape: { allow:boolean, type: "authentication"|"authorization", messages:[] }.
- Rules normalized by `RulesLoader` and stored in `properties.firewall.rules.inline`. Rule keys often used: `securelist`, `whitelist`, `httpMethods`, `allowedIPs`, `action`, `redirect`, `overrideEvent`.
- When modifying or adding handlers, prefer ColdBox handler metadata (annotations) for security: see `test-harness/handlers/*` and `handlers/Jwt.cfc` for examples.
- JWT integration relies on `models/jwt/JwtService.cfc` + `models/jwt/storages/*` and `jwt-cfml` dependency; preserve token storage API when changing.

5) Events & integration points
- Interceptor announces: `cbSecurity_onInvalidAuthentication`, `cbSecurity_onInvalidAuthorization`, `cbSecurity_onFirewallBlock` and many JWT lifecycle events (see `ModuleConfig.cfc` interceptorSettings).
- Modules can register rules in their `ModuleConfig.cfc` and are merged into the global rules by `interceptors/Security.cfc` (see `registerModule()` / `postModuleLoad`).

6) Tests & test-harness specifics
- Test harness lives in `test-harness/`. It contains a minimal ColdBox app and TestBox specs (`test-harness/tests/specs/*`). Use it to run integration specs locally.
- Runner: `test-harness/tests/runner.cfm` expects a running CF server on port 60299. Start via `box server start` using one of `server-*.json` files.

7) Small, high-value tasks for AI agents
- Add a focused unit test for a validator method in `test-harness/tests/specs/unit/`.
- When changing behavior in `Security.cfc`, update `test-harness/tests/specs/integration/*` to cover rule matching and invalid action flows.
- Preserve WireBox IDs and signatures when changing services (e.g. `authenticationService@cbauth`, `CacheStorage@cbstorages`).

8) Safety and CI
- CI uses the `build/Build.cfc` and `box.json` scripts. Do not modify CI scripts without updating `box.json` and `build/Build.cfc`.

If anything above is unclear or missing (local server ports, preferred validator override patterns, or CI details), tell me which area to expand and I will iterate.
