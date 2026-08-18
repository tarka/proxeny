
# Quick Nushell script to fetch any outstanding .debs not present in
# the local repo.

use std/log

log info "Fetching local packages"
let repo_debs = aptly repo show -json -with-packages vicarian
  | from json
  | get Packages
  # aptly returns bare names (no .deb) so normalise with upstream
  | each { |pkg| $pkg + ".deb" }
print $repo_debs

log info "Fetching upstream packages"
let released_debs = http get 'https://api.github.com/repos/tarka/vicarian/releases'
  | get assets
  | flatten
  | where content_type == "application/x-debian-package"
  | get name
print $released_debs

log info "Diffing package lists to find needed"
let needed_pkgs = $released_debs
  | where $in not-in $repo_debs

if ( $needed_pkgs | is-empty ) {
  log info "No missing packages, exiting..."
  exit 0
}

let needed_vers = (
  $needed_pkgs
  | wrap deb
  | merge (
    $needed_pkgs
    | parse "vicarian_{version}-{debver}_{arch}.deb"
  )
)
print $needed_vers

let tmpdir = mktemp -d

log info "Starting download of outstanding debs..."
for needed in $needed_vers {
  let url = $"https://github.com/tarka/vicarian/releases/download/v($needed.version)/($needed.deb)"
  log info $"Fetching ($url)..."
  http get $url | save $"($tmpdir)/($needed.deb)"
}

log info "Adding downloaded debs to repo..."
aptly repo add vicarian $tmpdir

log info "Updating repo"
aptly publish update stable

log info "Cleaning up temp directory"
rm --permanent --recursive --force $tmpdir

log info "Done"
