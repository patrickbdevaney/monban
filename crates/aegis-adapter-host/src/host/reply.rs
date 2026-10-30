//! Serializing handler results into HTTP replies (sdk-trybuild M4: markup returned as a `String`).
//!
//! F7 has no HTML builder, and a handler may still return markup in a `String`. The host therefore never lets a
//! handler choose a content type: every handler value maps through the sealed [`Respond`] trait to a fixed,
//! non-HTML content type, and every reply carries `X-Content-Type-Options: nosniff` (so no browser sniffs a
//! `text/plain` body into HTML), `Content-Security-Policy: default-src 'none'; sandbox` and `Cache-Control:
//! no-store`. Applications cannot implement [`Respond`] (sealed), so no app type can opt into `text/html`.
//! Errors map uniformly (W6): `Denied` is 404 whether the capability or the row was missing.
//!
//! An application type cannot opt into its own content type:
//!
//! ```compile_fail,E0277
//! use aegis_adapter_host::host::reply::{HttpReply, Respond, reply};
//! struct Html(String);
//! impl Respond for Html {
//!     fn into_reply(self) -> HttpReply { unimplemented!() }
//! }
//! ```

use aegis_sdk::SdkError;

pub const TEXT_PLAIN: &str = "text/plain; charset=utf-8";
pub const APPLICATION_JSON: &str = "application/json";
pub const OCTET_STREAM: &str = "application/octet-stream";
pub const EVENT_STREAM: &str = "text/event-stream";

/// Headers on every reply produced here, besides `content-type`.
pub const FIXED_HEADERS: [(&str, &str); 3] = [
    ("x-content-type-options", "nosniff"),
    ("content-security-policy", "default-src 'none'; sandbox"),
    ("cache-control", "no-store"),
];

/// A serialized handler reply. The content type is one of the constants above, never handler-chosen.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HttpReply {
    pub status: u16,
    content_type: &'static str,
    pub body: Vec<u8>,
}

impl HttpReply {
    pub fn content_type(&self) -> &'static str {
        self.content_type
    }

    /// Every header of the reply: `content-type` first, then [`FIXED_HEADERS`].
    pub fn headers(&self) -> [(&'static str, &'static str); 4] {
        let [a, b, c] = FIXED_HEADERS;
        [("content-type", self.content_type), a, b, c]
    }

    fn new(status: u16, content_type: &'static str, body: Vec<u8>) -> HttpReply {
        HttpReply { status, content_type, body }
    }
}

mod sealed {
    pub trait Sealed {}
}

/// A JSON body produced by the application. Served as `application/json` with nosniff (never rendered as HTML).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Json(pub String);

/// Handler response types the host can serialize. Sealed: the set of content types is fixed here.
pub trait Respond: sealed::Sealed {
    fn into_reply(self) -> HttpReply;
}

impl sealed::Sealed for String {}
impl Respond for String {
    fn into_reply(self) -> HttpReply {
        HttpReply::new(200, TEXT_PLAIN, self.into_bytes())
    }
}

impl sealed::Sealed for &'static str {}
impl Respond for &'static str {
    fn into_reply(self) -> HttpReply {
        HttpReply::new(200, TEXT_PLAIN, self.as_bytes().to_vec())
    }
}

impl sealed::Sealed for Vec<u8> {}
impl Respond for Vec<u8> {
    fn into_reply(self) -> HttpReply {
        HttpReply::new(200, OCTET_STREAM, self)
    }
}

impl sealed::Sealed for Json {}
impl Respond for Json {
    fn into_reply(self) -> HttpReply {
        HttpReply::new(200, APPLICATION_JSON, self.0.into_bytes())
    }
}

impl sealed::Sealed for () {}
impl Respond for () {
    fn into_reply(self) -> HttpReply {
        HttpReply::new(204, TEXT_PLAIN, Vec::new())
    }
}

/// HTTP status of an SDK error (uniform, W6).
pub fn error_status(e: SdkError) -> u16 {
    match e {
        SdkError::Denied => 404,
        SdkError::Conflict => 409,
        SdkError::Unavailable => 503,
    }
}

/// Serialize one handler result.
pub fn reply<R: Respond>(r: Result<R, SdkError>) -> HttpReply {
    match r {
        Ok(v) => v.into_reply(),
        Err(e) => HttpReply::new(error_status(e), TEXT_PLAIN, Vec::new()),
    }
}
