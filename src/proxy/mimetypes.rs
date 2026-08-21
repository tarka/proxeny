use http::{
    HeaderMap, HeaderValue,
    header::{CONTENT_ENCODING, CONTENT_TYPE},
};

// Compressible mime-types; generated from mime-db:
//
//     curl -fsSL "https://raw.githubusercontent.com/jshttp/mime-db/refs/heads/master/src/custom-types.json" \
//         | jq -r 'to_entries[] | select(.value.compressible == true) | .key'
//         | sort
//
const COMPRESSIBLE: &[&str] = &[
    "application/dart",
    "application/ecmascript",
    "application/javascript",
    "application/json",
    "application/octet-stream",
    "application/postscript",
    "application/raml+yaml",
    "application/rdf+xml",
    "application/rtf",
    "application/tar",
    "application/toml",
    "application/vnd.dart",
    "application/vnd.ms-fontobject",
    "application/vnd.ms-opentype",
    "application/wasm",
    "application/x-httpd-php",
    "application/x-ipynb+json",
    "application/x-javascript",
    "application/xml",
    "application/xml-dtd",
    "application/x-ns-proxy-autoconfig",
    "application/x-sh",
    "application/x-tar",
    "application/x-virtualbox-hdd",
    "application/x-virtualbox-ova",
    "application/x-virtualbox-ovf",
    "application/x-virtualbox-vbox",
    "application/x-virtualbox-vdi",
    "application/x-virtualbox-vhd",
    "application/x-virtualbox-vmdk",
    "application/x-www-form-urlencoded",
    "application/yaml",
    "font/otf",
    "font/ttf",
    "image/bmp",
    "image/vnd.adobe.photoshop",
    "image/vnd.microsoft.icon",
    "image/vnd.ms-dds",
    "image/x-icon",
    "image/x-ms-bmp",
    "message/rfc822",
    "model/gltf-binary",
    "text/cache-manifest",
    "text/cmd",
    "text/css",
    "text/csv",
    "text/html",
    "text/javascript",
    "text/jsx",
    "text/less",
    "text/markdown",
    "text/mdx",
    "text/n3",
    "text/plain",
    "text/richtext",
    "text/rtf",
    "text/tab-separated-values",
    "text/uri-list",
    "text/vcard",
    "text/vtt",
    "text/x-component",
    "text/x-gwt-rpc",
    "text/x-jquery-tmpl",
    "text/x-markdown",
    "text/xml",
    "text/x-org",
    "text/x-php",
    "text/x-processing",
    "text/x-suse-ymp",
    "text/yaml",
    "x-shader/x-fragment",
    "x-shader/x-vertex",
];


pub fn is_compressible(headers: &HeaderMap<HeaderValue>) -> bool {
    headers.get(CONTENT_ENCODING).is_none()  // Not already compressed
        && headers.get(CONTENT_TYPE)
        .and_then(|ct| ct.to_str().ok())
        .map(|ct| {
            // Trim trailing parameters (e.g: "...; charset=utf-8")
            let mime = ct.split(';')
                .next().unwrap_or(ct)
                .trim();
             // See https://github.com/jshttp/mime-db/blob/master/src/custom-suffix.json
             mime.ends_with("+json")
             || mime.ends_with("+xml")
             || COMPRESSIBLE.contains(&mime)
        })
        .unwrap_or(false)
}
