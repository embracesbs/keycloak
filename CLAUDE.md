# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this repository is

This is **embracesbs/keycloak**, Embrace's fork of upstream [keycloak/keycloak](https://github.com/keycloak/keycloak). It tracks upstream releases on branches named `releases/embrace/<version>` (current: `releases/embrace/26.4.0`, forked from `master`). Embrace-specific changes are cherry-picked/layered on top of the pristine upstream release so they can be re-applied when rebasing onto a new upstream version.

When upgrading to a new upstream version, the workflow is: take the upstream release, then re-apply the Embrace commits (see "Embrace customizations" below). **Keep Embrace changes minimal, localized, and traceable** — every edit you make to upstream files is something a future human has to forward-port.

## Build, test, run

Requires **JDK 17 or 21** (newer JDKs are unsupported). Always use the Maven wrapper `./mvnw` (or `mvnw.cmd` on Windows), not a system Maven.

```bash
./mvnw clean install                                   # build all modules + run testsuite
./mvnw -pl quarkus/deployment,quarkus/dist -am -DskipTests clean install   # build server only
./mvnw clean install -Pdistribution                    # build with adapters
./mvnw clean install -Poperator -DskipTests            # operator module (excluded by default)
```

Run a built server:
```bash
java -jar quarkus/server/target/lib/quarkus-run.jar start-dev
```

Run a single test (standard Surefire/Failsafe):
```bash
./mvnw test -pl services -Dtest=SomeTestClass#someMethod
```

Useful flags:
- `-DskipProtoLock=true` — skip proto-schema-compatibility checks (these fail behind proxies; relevant because committing `**/proto.lock` changes is a recurring task here).
- `-Dmaven.build.cache.enabled=true` — opt-in incremental build cache.
- `-Dbrowser=chrome|firefox` — testsuite browser (default HtmlUnit).

For deeper test docs see `docs/tests.md`, `docs/tests-development.md`, and `testsuite/integration-arquillian/HOW-TO-RUN.md`. Build details: `docs/building.md`.

### IDE note
Parts of the project depend on Maven-generated sources. Build once with Maven first, then in IntelliJ use **Build → Build Project** (not **Rebuild Project**, which deletes generated classes).

## Versioning

Version bumps are scripted — do not hand-edit versions across the ~100 POMs:
```bash
./set-version.sh 26.4.0    # updates Maven POMs, npm package.json files, Dockerfile, docs attributes
./get-version.sh           # prints current version
```

## Module map (Maven reactor)

Standard upstream layout. Big picture, from low- to high-level:
- `core` — representations, constants, shared model interfaces (e.g. `org.keycloak.models.*Model`, `org.keycloak.representations.idm.*`).
- `server-spi`, `server-spi-private` — provider SPIs that the rest of the server implements/consumes.
- `model` — persistence (JPA entities/providers under `org.keycloak.models.jpa`).
- `services` — the bulk of server logic: admin REST resources (`services/.../resources/admin`), managers (`RealmManager`, `ClientManager`), and bootstrap (`KeycloakApplication`).
- `authz` — fine-grained authorization.
- `quarkus` — the runtime distribution (`quarkus/dist`, `quarkus/server`, `quarkus/container/Dockerfile`).
- `js` — `admin-ui`, `account-ui`, `keycloak-admin-client`, `ui-shared` (npm workspaces).
- `test-framework`, `tests`, `testsuite` — newer test framework, newer tests, and legacy Arquillian testsuite respectively.
- `adapters`, `federation`, `saml-core`, `crypto`, `operator`, `themes` — as named.

## Embrace customizations

The major customization is **Multi-Tenancy support**, which spans `core`, `model`, and `services`. There is no separate "Embrace module" — changes are edits inside upstream files. **To find them, grep for `Embrace` and for `EmbraceMultiTenantConstants`** rather than relying on comments (many edits are unmarked).

Key pieces:
- `core/.../constants/EmbraceMultiTenantConstants.java` — central constants: client scope prefix `identity-provider-user-` and the `identity-provider` client id.
- New admin role `QUERY_MULTITENANT_CLIENT_IDS` (in `core/.../models/AdminRoles.java`).
- `services/.../managers/RealmManager.java` and `ClientManager.java` — tenant realm / client wiring, per-realm client scopes, identity-provider protocol mappers.
- Admin REST changes in `services/.../resources/admin/` (`ClientResource`, `ClientsResource`, `RoleResource`, `RoleContainerResource`) and FGAP permission changes under `resources/admin/fgap/`.
- `ResourceServerDefaultPermissionCreator.java` (added).

**One-time data migrations** live in `services/.../resources/KeycloakApplication.java` as `embraceMigration01/02/03(...)`. They run at server startup **only when** `-DrunEmbraceMigrations=true` is set, each guarded to be idempotent (it checks whether the migration already ran before mutating data). When adding a migration, follow the same once-run + idempotency-guard pattern.

Other Embrace edits touch `JpaUserProvider`, `UserModel`, `OIDCIdentityProvider`, and `UsersResource` (see commit `Other Embrace modifications`).
