### Quick orientation — cbsecurity (ColdBox module)

This repository is a ColdBox module that provides a request firewall, annotation-driven security, JWT handling, CSRF integration, and security headers.

Keep guidance short and actionable. Prefer small, verifiable edits and reference the real files below.

1) Big picture
- ColdBox module: entrypoint and wiring in `ModuleConfig.cfc` and `models/CBSecurity.cfc`.
- Runtime protection happens in the `cbsecurity.interceptors.Security` interceptor (`interceptors/Security.cfc`) which:
  - loads and normalizes rules via `helpers/RulesLoader` (see `models/util/RulesLoader.cfc`),
  - delegates validation to a Validator (default: `models/validators/AuthValidator.cfc`) via `ruleValidator()` and `annotationValidator()`,
  - processes rule actions (redirect/override/block) and emits interception events (`cbSecurity_onInvalidAuthentication`, etc.).
- Bundled sub-modules: `modules/cbauth/` (authentication), `modules/cbcsrf/` (CSRF protection), `modules/jwtcfml/` (JWT library).

2) Source layout at a glance
- **Business logic & APIs**: `models/` — `CBSecurity.cfc`, `jwt/JwtService.cfc`, `auth/` (BasicAuth), `delegates/` (Auth, Authorizable, JwtSubject), `validators/*` (5 validators), `util/` (RulesLoader, DBLogger).
- **Request enforcement**: `interceptors/Security.cfc` (rule matching, IP/HTTP method validation, event overrides) and `interceptors/SecurityHeaders.cfc`.
- **Handlers**: `handlers/BasicAuth.cfc`, `handlers/Jwt.cfc`, `handlers/Visualizer.cfc`.
- **Interfaces**: `interfaces/IAuthService.cfc`, `IAuthUser.cfc`, `IModelRules.cfc`, `ISecurityValidator.cfc`, `IUserService.cfc`, `jwt/IJwtStorage.cfc`, `jwt/IJwtSubject.cfc`.
- **Helpers**: `helpers/mixins.cfm` (mixin injections).
- **Config**: `config/Router.cfc`, `config/security.json.cfm`, `config/security.xml.cfm`, `config/securityrules.sql`.
- **Views**: `views/home/` (dashboard with tabs: activity, authentication, basicAuth, csrf, firewall, jwt, rules, security-headers).
- **Migrations**: `migrations/2023_03_28_225839_create_security_logs_table.cfc`.
- **Build/CI**: `build/Build.cfc`, `build/release.boxr`.
- **Module wiring**: `ModuleConfig.cfc` and `box.json` for dependencies and scripts.

3) Developer workflows (how to run, test, build)
- Install deps and test harness: `box install` at repo root, then `cd test-harness && box install` (or use `box install` from root — `box.json` has `install:dependencies`).
- Run local server for integration/test harness: `box server start server-lucee@5.json` (see `box.json` scripts `start:lucee` / `start:2023` / `start:2025` / `start:boxlang`).
- Run tests: this repo uses TestBox. The package `box.json` test runner is configured to `http://localhost:60299/tests/runner.cfm` and `build/Build.cfc` calls `testbox run`. Start the server, then open that URL or run `box testbox run runner=http://localhost:60299/tests/runner.cfm`.
- Useful npm-like tasks are defined in `box.json` under `scripts` (e.g. `box task run taskFile=build/Build.cfc` used by CI). In VSCode use the Task `Run CommandBox Task`.
- Server configs available: Lucee 5, Lucee 6, Adobe 2023, Adobe 2025, BoxLang, BoxLang CFML.

4) Patterns & conventions to follow
- Validators expose `ruleValidator(rule, controller)` and `annotationValidator(securedValue, controller)`. Return shape: { allow:boolean, type: "authentication"|"authorization", messages:[] }.
- Rules normalized by `RulesLoader` and stored in `properties.firewall.rules.inline`. Rule keys often used: `securelist`, `whitelist`, `httpMethods`, `allowedIPs`, `action`, `redirect`, `overrideEvent`.
- When modifying or adding handlers, prefer ColdBox handler metadata (annotations) for security: see `test-harness/handlers/*` and `handlers/Jwt.cfc` for examples.
- JWT integration relies on `models/jwt/JwtService.cfc` + `models/jwt/storages/*` (CacheTokenStorage, DBTokenStorage) and `modules/jwtcfml/` dependency; preserve token storage API when changing.
- WireBox IDs to preserve: `authenticationService@cbauth`, `CacheStorage@cbstorages`, `JwtService@cbsecurity`.

5) Events & integration points
- Interceptor announces: `cbSecurity_onInvalidAuthentication`, `cbSecurity_onInvalidAuthorization`, `cbSecurity_onFirewallBlock` and many JWT lifecycle events (see `ModuleConfig.cfc` interceptorSettings).
- Modules can register rules in their `ModuleConfig.cfc` and are merged into the global rules by `interceptors/Security.cfc` (see `registerModule()` / `postModuleLoad`).
- Module-level rules apps in `test-harness/modules_app/` (api, mod1) demonstrate per-module security config.

6) Tests & test-harness specifics
- Test harness lives in `test-harness/`. It contains a minimal ColdBox app and TestBox specs.
- Test specs: `test-harness/tests/specs/integration/` (BasicAuthUserService, CBSecuritySpec, JWTSpec, SecuritySpec) and `test-harness/tests/specs/unit/` (CBSecurityTest, SecurityTest).
- Test resources: `test-harness/tests/resources/` (Binder, security rules in CFC/JSON/XML formats).
- Runner: `test-harness/tests/runner.cfm` expects a running CF server on port 60299. Start via `box server start` using one of `server-*.json` files.
- Test harness handlers: `test-harness/handlers/admin.cfc`, `Annotations.cfc`, `jwt.cfc`, `Main.cfc`, `Public.cfc`, `PutPost.cfc`.

7) Small, high-value tasks for AI agents
- Add a focused unit test for a validator method in `test-harness/tests/specs/unit/`.
- When changing behavior in `Security.cfc`, update `test-harness/tests/specs/integration/*` to cover rule matching and invalid action flows.
- Preserve WireBox IDs and signatures when changing services (e.g. `authenticationService@cbauth`, `CacheStorage@cbstorages`).

8) Safety and CI
- CI uses the `build/Build.cfc` and `box.json` scripts. Do not modify CI scripts without updating `box.json` and `build/Build.cfc`.
- GitHub Actions workflows in `.github/workflows/`: cron, pr, release, snapshot, tests.
- `.env` file for local environment overrides (see `.env.example`).

9) AI agent skills (`.agents/skills/`)
- 71 skill definitions are available in `.agents/skills/`, sourced from ortus-boxlang/skills and coldbox/skills GitHub repos.
- **BoxLang (29)**: language fundamentals, OOP, async, caching, config, database, security, testing, web, CLI, CommandBox, miniserver, interceptors, modules, files, zip, scheduled tasks, cfml-migration, java-integration, docbox, code-documenter, code-reviewer, best-practices, functional-programming, templating, application-descriptor, file-watchers, ortus-coding-standards.
- **ColdBox (32)**: handler/interceptor/layout/module development, routing, REST API, event model, DI (WireBox), cache, async, logging, config, CLI, proxy, decorators, flash messaging, request context, AI integration, app layouts, view rendering, scheduled tasks, reviewer, documenter, testing (base classes, handler, http-methods, integration, interceptor, model), database-migrations, wirebox-aop.
- **TestBox (10)**: BDD, xUnit, assertions, expectations, mockbox, cbmockdata, runners, reporters, listeners, testing-coverage, testing-fixtures.
- Skills lock file: `skills-lock.json` tracks source hashes for all installed skills.

If anything above is unclear or missing (local server ports, preferred validator override patterns, or CI details), tell me which area to expand and I will iterate.
