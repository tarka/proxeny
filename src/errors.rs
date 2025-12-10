use camino::Utf8PathBuf;


/// Most errors are handled/created with anyhow, however some
/// transient errors may need to be handled differently.
#[derive(Debug, PartialEq, thiserror::Error)]
pub enum VicarianError {
    #[error("TLS Key & Cert don't match: {0}, {1}")]
    CertificateMismatch(Utf8PathBuf, Utf8PathBuf),
}
