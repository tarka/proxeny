# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.3.3](https://github.com/tarka/vicarian/compare/v0.3.2...v0.3.3) - 2026-08-18

### <!-- 1 -->Bug Fixes

- *(acme)* Add additional record test when polling DNS to ensure we have the right entry.
- *(acme)* Delete all matching DNS-01 ACME records on cleanup to prevent a pile-up of stale entries.

### <!-- 3 -->Documentation

- Simplify deb instructions.
- Add instructions for Debian package installation.

### Other

- Update to latest zone-update, and other dependencies.

## [0.3.2](https://github.com/tarka/vicarian/compare/v0.3.1...v0.3.2) - 2026-08-03

### Other

- Fix typo in binaries release.

## [0.3.1](https://github.com/tarka/vicarian/compare/v0.3.0...v0.3.1) - 2026-08-03

- Add build and upload of .deb packages.

### <!-- 3 -->Documentation

- Add basic static file config example.
- Change AI/LLM policy to "none"

### Other

- Add support for building .deb packages with cargo-deb
- Add simple inline SVG favicon.
- Update dependencies, and move the the now-beta upstream static-web-server

## [0.3.0](https://github.com/tarka/vicarian/compare/v0.2.6...v0.3.0) - 2026-07-21

### <!-- 1 -->Features

- Add static file support using static-web-server library. See CONFIGURATION.md for detail.

### <!-- 7 -->Miscellaneous Tasks

- Bump dependencies.
- Bump to 0.3.0

### Other

- Squashed 'vendor/static-web-server/' content from commit 13228a9

## [0.2.6](https://github.com/tarka/vicarian/compare/v0.2.5...v0.2.6) - 2026-06-08

### <!-- 1 -->Bug Fixes

- We technically need the tokio  flag, although it's enabled by other dependencies.
- Add fix for bare-IPv6 port-stripping.
- Handle hostnames case-insensitively

### <!-- 3 -->Documentation

- Add SECURITY.md

### Other

- Bump dependencies; include Pingora security fixes.
- We can use OnceLock rather than tokio-specific version
- Minor test fix
- Dependency upgrade
- Dependency bump.
- Add ACME renewal success/fail counters.
- Move metrics names into consts in metrics module and register/describe them up front.
- Minor dependency updates.
- Update github action version.

## [0.2.5](https://github.com/tarka/vicarian/compare/v0.2.4...v0.2.5) - 2026-03-11

### <!-- 0 -->Features

- Add support for simple `Bearer <key>` authorisiation

### <!-- 1 -->Bug Fixes

- Print next expirng in local timezone.

### <!-- 3 -->Documentation

- Add docs for auth_key
- Typo
- Add note about using metrics and ACME timeout in prometheus/grafana

### Other

- Remove old debugging log
- Move metrics documentation to own file.
- Better Grafana tips.

## [0.2.4](https://github.com/tarka/vicarian/compare/v0.2.3...v0.2.4) - 2026-03-10

### <!-- 0 -->Features

- Add support for Prometheus metrics, including serving over TLS.

### <!-- 1 -->Bug Fixes

- Fix metric name

### <!-- 3 -->Documentation

- Update docs and add examples for metrics.

### Other

- Minor readme update
- Move generic headers to response_filter()
- Add simple test for metrics endpoint
- Small comment update
- Cleanup some errors.
- Initial prometheus response
- Make metrics global (as the recorder is anyway) and start wiring up request
- Move backend lookup to the initial request and store in the context.
- Convert Backend router storage to be arc.
- Rename module URL test
- Add test for using URI scheme to direct to component backends
- Start of wiring up metrics to HTTPS.
- Start setting up metrics runtime

## [0.2.3](https://github.com/tarka/vicarian/compare/v0.2.2...v0.2.3) - 2026-03-07

### Other

- Fixes and cleanups for renewal time logic.
- Remove redundant unit return
- Return an error rather than panicing on unexpected Acme status.
- Fix clippy warning in test utils.
- Convert to using time crate and std for datetime
- Add doc to HostCertificate
- Impl Clone for HostCert and remove all Arc wrappers.
- Add some error clarifications.
- Start of converting HostCert to us an inner arc.
- Remove dependency on boring to avoid clashes with pingora-boringssl
- Bump dependencies

## [0.2.2](https://github.com/tarka/vicarian/compare/v0.2.1...v0.2.2) - 2026-03-07

### <!-- 1 -->Bug Fixes

- Avoid using common port numbers in tests.

### Other

- Fix LetsEncrypt renewal window handling.
- Fixes to handling the next timeout.
- Initial impl of acme retry logic.
- rustls-pemfile is deprecated; us PemObject instead.
- Bump dependencies
- Remove some old dev dependencies.
- Move rustls-pemfile to dev.
- Minor cleanups.
- Add localhost certificate and use for websocket testing.
- Initial non-working attempt.
- More cert store fixes.
- Add loading of generated test certs as a rustls root store.
- Remove duplication in test cert generation
- Update comments and make certificate runtime single-threaded.
- Big refactor to move all certificate-related processing under a common runtime
- Tweaks and cleanups before futher refactoring.
- Intial cut of async host certs (and many knock-on effects)
- Update to Pingora 0.7.0
- Remove old test dependencies from cargo

## [0.2.1](https://github.com/tarka/vicarian/compare/v0.2.0...v0.2.1) - 2026-01-30

### <!-- 0 -->Features

- Allow specifying listening on an interface with the "if#" prefix.

### <!-- 1 -->Bug Fixes

- Increase the FD limit on startup.

### Other

- Add docs and examples for interface listener
- Merge branch 'sockaddr-interface'
- Remove obsolete clippy directive.
- Convert to using SocketAddr internally to preserve IPv6 link-local scope-ids
- Add ipv6 text conversion test.
- Working versin with SockAddr propogation.
- Convert to modified sockaddr pingora version
- Link to local pingora master.
- More cleanups and testing for IF expansion.
- Start of interface address expansion
- Remove obsolete early dev test.
- Bump dependencies.

## [0.2.0](https://github.com/tarka/vicarian/compare/v0.1.17...v0.2.0) - 2026-01-23

### <!-- 0 -->Features

- Add generation of wildcard certs with ACME DNS-01
- [**breaking**] Add ability to listen on multiple ip addresses. This changes the config file format; `addr` is now `addrs` and is a list.

### <!-- 1 -->Bug Fixes

- Add the crt/key suffix to certfiles rather than replacing the root.

### <!-- 3 -->Documentation

- Update docs with wildcard information

### <!-- 4 -->Performance

- Enable LTO for release. Also enable runtime overflow checks.

### Other

- Hack to support testing of wildcard example config.
- Normalise IPs before initialising listener.
- Simplify release profile.
- Use corrected release-plz config.
- Dependency bump
- Fix README AI section.
- Dependency bump to fix boring-ssl issues.
- Dependency bump and tweak README.
- Update dependencies and simplify AI statement.
- Clarify wildcard position.
- Add more release-plz tag categrories.

## [0.1.17](https://github.com/tarka/vicarian/compare/v0.1.16...v0.1.17) - 2026-01-08

### Other

- Add notes about HTTP/3 and h2c.
- Add HTTP/2 support and testing.
- Simplify tls-only references.

## [0.1.16](https://github.com/tarka/vicarian/compare/v0.1.15...v0.1.16) - 2026-01-08

### Other

- Add not about tech stack.
- Expand on static file updates.
- Update to recommend static-web-server over python.
- Soften the tone in AI section.
- minor readme updates.
- Add note about tarball layout.

## [0.1.15](https://github.com/tarka/vicarian/compare/v0.1.14...v0.1.15) - 2026-01-07

## Notable changes

- Added support for LetsEncrypt 'classic' profile.

### Other

- Add LE classic profile
- Add rust-caching to binary release

## [0.1.14](https://github.com/tarka/vicarian/compare/v0.1.13...v0.1.14) - 2026-01-07

### Notable changes

- HSTS headers are now set automatically.
- The configuration examples are now shipped in the binary tarball.
- The placeholder webpage is now in the repository.
- Documentation updates.

### Other

- Move happy-eyeballs to todos
- Add code of conduct.
- Fix license link
- Add HSTS header and test.
- Note on secrets.
- More readme
- More readme updates.
- Update some config fragments on the webpage.
- Import generated website page from earlier experiment.
- Ship the examples directory with the tarball.

## [0.1.13](https://github.com/tarka/vicarian/compare/v0.1.12...v0.1.13) - 2026-01-07

### Other

- Move to single-phase release-plz workflow.
- Cleanups from clippy
- Add test for invalid cert.
- Dependency bump
- Add test for vhosts.
- Add note about nextest.
- Move more of the test cert generation into the common certs module.
- Use the CA root generated www.example.com cert in unit tests.
- Add nextest config so integration tests are serial.
- Rename unit and integration test wrappers for clarity.
- Generate cert-dir pathbuf globally
- Add note about cert utils in tests.
- More cleanup.
- Integration tests with unit tests for now.
- Minor cleanup.
- Finalise move to runtime generated certs.
- Start of test CA generation
- Start splitting test cert-generation code out.
- Split proxy runner code into submodule.
- Start moving common test code into its own module
- Add some more notes to tests.
- Intial backend mocking test with wiremock.
- Convert to async.
- Initial test using root cert override.
- Move integration tests into a module for cleaner setup.
- Save test files on panic/assert.
- Initial working integration test.
- Use builder pattern.
- Start of integration tests.
- Add dir-locals to gitignore.
- Enable clippy in emacs/rustic/eglot.
- Remove MSRV for now.
- Tweaks to support cargo-binstall
- Bump dependencies.
- More docs tweaks
- Documentation updates
- Add deny_unknown_fields to config structures.
- Simplify non-TLS setup by enabling on port being set or HTTP-01 ACME.
- More error context.
- Force enum string into lower case.
- Add configurable ACME profiles.
- Update config docs.
- Merge branch 'vhosts'
- Tidy up pingora error handling.
- Dependency update

## [0.1.12](https://github.com/tarka/vicarian/compare/v0.1.11...v0.1.12) - 2025-12-23

### Other

- Change the shortlived renewal window to something sensible.
- Also disable Mac binaries.
- Give up on trying to make FreeBSD & MacOS work for now.
- Correct import.
- Missing import for mac
- Use pollwatcher on Mac.
- More workflow fixes.
- Tweaks to FreeBSD testing script.
- Allow default features on notify to enable mac events.
- Be more explicit about test certs
- Override subject default.
- Use standard ubuntu version.
- Use rcgen rather than openssl for test certs as openssl versions are all over the place.
- Try using newer ubuntu
- Yaml fixes.
- Yaml fixes.
- More ssl probes.
- Find openssl version
- Typo in workflow.
- More logging of openssl runs.
- Add rust caching to unit test build.
- Remove some unnecessary dev-deps
- Add MSRV
- First cut of unit-test workflow.
- Minor cleanup.

## [0.1.11](https://github.com/tarka/vicarian/compare/v0.1.10...v0.1.11) - 2025-12-22

### Other

- Correct shortarch ref
- More path tweaks

## [0.1.10](https://github.com/tarka/vicarian/compare/v0.1.9...v0.1.10) - 2025-12-22

### Other

- Remove unnecessary release-name check.

## [0.1.9](https://github.com/tarka/vicarian/compare/v0.1.8...v0.1.9) - 2025-12-22

### Other

- Initial attempt at a cleaner release tarball.

## [0.1.8](https://github.com/tarka/vicarian/compare/v0.1.7...v0.1.8) - 2025-12-22

### Other

- Try re-enabling Mac ARM builds

## [0.1.7](https://github.com/tarka/vicarian/compare/v0.1.6...v0.1.7) - 2025-12-22

### Other

- Try running the ARM release on the ARM64 runner
- BoringSSL doesn't work on ARM either?

## [0.1.6](https://github.com/tarka/vicarian/compare/v0.1.5...v0.1.6) - 2025-12-22

### Other

- Continue building other binaries if one fails.
- Remove musl as it doesn't work with non-GNU libc

## [0.1.5](https://github.com/tarka/vicarian/compare/v0.1.4...v0.1.5) - 2025-12-22

### Other

- Try only running release on PR merge.
- Disable Mac & FreeBSD binaries for now until we have testing for them in place.

## [0.1.4](https://github.com/tarka/vicarian/compare/v0.1.3...v0.1.4) - 2025-12-22

### Other

- Remove windows releases.

## [0.1.3](https://github.com/tarka/vicarian/compare/v0.1.2...v0.1.3) - 2025-12-22

### Other

- Correct binary name.

## [0.1.2](https://github.com/tarka/vicarian/compare/v0.1.1...v0.1.2) - 2025-12-22

### Other

- Add crates.io installtion to README
- Add initial binary release workflow

## [0.1.1](https://github.com/tarka/vicarian/compare/v0.1.0...v0.1.1) - 2025-12-22

### Other

- Remove obsolete external directory.
- Re-allow external readme file.
- Use explicit job steps.
- Another attempt
- Try removing dispatch.
- Simplify dispatch.
- More workflow tweaks
- Workflow tweaks
- Spit manual and automatic steps.
- Initial release-plz configuration.
- Add fuzzyness to cert renewal timeout.
- Correct wait period conversion.
- Example config update
- Conf docs updates.
- Bump dependencies.
- More tightening-up of the config file format.
- More documentation updates.
- Correct corn link
- Updates to example config files and add a draft CONFIGURATION.md
- Fixes to service file.
- Make tx end of quit queue private.
- Watcher cleanup.
- Cleanup handling of ACME certificate configuration and expiry handling.
- Normalise all time calculations on Chrono and second resolution.
- Add ability to trust a HTTPS backend with self-signed certs.
- Reduce request logging.
- Header cleanup.
- Add Via: header
- Logging cleanup.
- Dogfooding with the new shortlived ACME profile.
- Initial support for application context handling.
- Big refactor of cert handling that removes the assumption of Subject: being the hostname. This also allows us to use the 'tlscert' profile, and 'shortlived' eventually.
- Use local instant-acme with our patches for the time being.
- Better handling of expiring certs.
- Handle hosts with multiple aliases.
- Fixes from adding locally
- Re-add handling multiple authorisations.
- Remove erroneous option check on insert.
- Update and expand example configs.
- First cut of HTTP-01 challenge response.
- Start of refactoring to support ACME HTTP-01
- Remove domain from config in favour of calcuating it from the PSL.
- Add loading and saving account credentials.
- Update zone-update
- Zone-updated reverted API changes.
- Move to new zone-update API, plus misc. cleanups.
- Update gitignore.
- Dependency bump
- Move config into config dir and split out tests.
- Move proxy tests into own submodule.
