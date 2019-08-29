use std::convert::AsRef;
use std::sync::{Arc, Mutex};

use futures::prelude::*;
use futures::stream::Stream;
use futures::sync::oneshot;
use hyper;
use hyper::{header, StatusCode, Uri};
use url::form_urlencoded;
use url::percent_encoding::{percent_encode, QUERY_ENCODE_SET};

use crate::authenticator_delegate::FlowDelegate;
use crate::types::{ApplicationSecret, GetToken, RequestError, Token};


/// Assembles a URL to request an authorization token (without user interaction)
fn build_authentication_request_url<'a, T, I>(
    auth_uri: &str,
    client_id: &str,
    scopes: I,
    redirect_uri: Option<String>,
) -> String
where
    T: AsRef<str> + 'a,
    I: IntoIterator<Item = &'a T>,
{
    let mut url = String::new();
    let mut scopes_string = scopes.into_iter().fold(String::new(), |mut acc, sc| {
        acc.push_str(sc.as_ref());
        acc.push_str(" ");
        acc
    });
    // Remove last space
    scopes_string.pop();

    url.push_str(auth_uri);
    vec![
        format!("?scope={}", scopes_string),
        format!("&access_type=offline"),
        format!("&include_granted_scopes=true")
        format!(
            "&redirect_uri={}",
            redirect_uri.expect("redirect_uri should be provided")
        ),
        format!("&response_type=code"),
        format!("&client_id={}", client_id),
    ]
    .into_iter()
    .fold(url, |mut u, param| {
        u.push_str(&percent_encode(param.as_ref(), QUERY_ENCODE_SET).to_string());
        u
    })
}
