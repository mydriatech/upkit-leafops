/*
    Copyright 2025 MydriaTech AB

    Licensed under the Apache License 2.0 with Free world makers exception
    1.0.0 (the "License"); you may not use this file except in compliance with
    the License. You should have obtained a copy of the License with the source
    or binary distribution in file named

        LICENSE-Apache-2.0-with-FWM-Exception-1.0.0

    Unless required by applicable law or agreed to in writing, software
    distributed under the License is distributed on an "AS IS" BASIS,
    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
    See the License for the specific language governing permissions and
    limitations under the License.
*/

//! HTTP client errors.

use std::error::Error;
use std::fmt;

/// Cause of error.
#[derive(Debug)]
pub enum HttpClientErrorKind {
    /// Generic failure
    Failure,
    /// Request is too large for HTTP GET
    TooLargeForHttpGet,
    /// HTTP Error response.
    HttpErrorCode(u16),
}

impl HttpClientErrorKind {
    /// Create a new instance with an error message.
    pub fn error_with_msg(self, msg: &str) -> HttpClientError {
        HttpClientError {
            kind: self,
            msg: Some(msg.to_string()),
        }
    }

    /// Create a new instance without an error message.
    pub fn error(self) -> HttpClientError {
        HttpClientError {
            kind: self,
            msg: None,
        }
    }
}

impl fmt::Display for HttpClientErrorKind {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{:?}", self)
    }
}

/** HTTP client error.

Create a new instance via [HttpClientErrorKind].
*/
#[derive(Debug)]
pub struct HttpClientError {
    kind: HttpClientErrorKind,
    msg: Option<String>,
}

impl HttpClientError {
    /// Return the type of error.
    pub fn kind(&self) -> &HttpClientErrorKind {
        &self.kind
    }
}

impl fmt::Display for HttpClientError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        if let Some(msg) = &self.msg {
            write!(f, "{} {}", self.kind, msg)
        } else {
            write!(f, "{}", self.kind)
        }
    }
}

impl Error for HttpClientError {}
