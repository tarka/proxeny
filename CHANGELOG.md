# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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
