extern crate derp;
extern crate untrusted;

use derp::Tag;
use std::fmt;
use untrusted::Input;

/// 1.2.840.113549.1.5.13 pkcs5PBES2(PKCS #5 v2.0)
const PKCS8_V2_OID: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x05, 0x0d];

/// 1.3.6.1.4.1.11591.4.11 scrypt
const SCRYPT_OID: &[u8] = &[0x2B, 0x06, 0x01, 0x04, 0x01, 0xDA, 0x47, 0x04, 0x0B];

#[derive(PartialEq, Clone, Debug)]
pub struct Error {}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        fmt::Debug::fmt(self, f)
    }
}

impl ::std::error::Error for Error {
    fn description(&self) -> &str {
        "Pkcs8 Error"
    }
}

impl From<derp::Error> for Error {
    fn from(_: derp::Error) -> Self {
        Self {}
    }
}

pub type Result<T> = ::std::result::Result<T, Error>;

struct Pkcs8<'a> {
    encrypted_key: &'a [u8],
}

pub struct Pkcs8Options<'a> {
    passphrase: Option<&'a [u8]>,
}

impl<'a> Default for Pkcs8Options<'a> {
    fn default() -> Self {
        Self {
            passphrase: None,
        }
    }
}

pub fn pkcs8_encrypt<'a, K>(key: K, out: &mut Vec<u8>, options: &Pkcs8Options<'a>) -> Result<()>
where
    K: Into<&'a [u8]>
{
    panic!() // TODO
}

pub fn pkcs8_decrypt<'a, K>(key: K, out: &mut Vec<u8>) -> Result<()>
where
    K: Into<&'a [u8]>
{
    let pkcs8 = parse_pkcs8(key.into())?;
    panic!() // TODO
}

fn parse_pkcs8<'a>(key: &'a [u8]) -> Result<Pkcs8<'a>> {
    let input = Input::from(key);
    let pkcs8 = input.read_all(derp::Error::Read, |input| {
        derp::nested(input, tag::sequence, |input| {
            if derp::expect_tag_and_get_value(input, Tag::Oid)? != PKCS8_V2_OID {
                return Err(derp::Error::WrongValue);
            }

            derp::nested(input, tag::sequence, |input| {
            })?;
            Ok(()) // TODO
        })?;
        let encrypted_key = derp::expect_tag_and_get_value(input, Tag::OctetString)?;

        Ok(Pkcs8 {
            encrypted_key: encrypted_key.as_slice_less_safe(),
        })
    })?;

    Ok(pkcs8)
}

#[cfg(test)]
mod test {
    use super::*;
}
