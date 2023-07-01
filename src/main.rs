use std::error::Error;
use std::fmt;
use trust_dns_resolver::TokioAsyncResolver;
use trust_dns_resolver::config::{ResolverConfig, ResolverOpts};
use trust_dns_resolver::error::ResolveError;
use trust_dns_resolver::proto::rr::{RecordType, RData};
use url::{ParseError, Url};

#[derive(Debug)]
pub enum TxtRecordError {
    UrlParseError(ParseError),
    NoDomainInUrl,
    DnsResolutionError(ResolveError),
}

impl fmt::Display for TxtRecordError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "Error checking TXT record: {:?}", self)
    }
}

impl Error for TxtRecordError {}

impl From<url::ParseError> for TxtRecordError {
    fn from(err: url::ParseError) -> TxtRecordError {
        TxtRecordError::UrlParseError(err)
    }
}

impl From<trust_dns_resolver::error::ResolveError> for TxtRecordError {
    fn from(err: trust_dns_resolver::error::ResolveError) -> TxtRecordError {
        TxtRecordError::DnsResolutionError(err)
    }
}

pub async fn check_txt_record(
    resolver: &TokioAsyncResolver,
    domain_url: &str,
    expected_record: &str,
) -> Result<bool, TxtRecordError> {
    let url = Url::parse(domain_url)?;
    let domain = url
        .domain()
        .ok_or(TxtRecordError::NoDomainInUrl)?;

    let response = resolver
        .lookup(domain, RecordType::TXT)
        .await?;

    for record in response.iter() {
        if let RData::TXT(txt_data) = record {
            for txt in txt_data.iter() {
                let txt_string = String::from_utf8_lossy(txt);
                if txt_string == expected_record {
                    return Ok(true);
                }
            }
        }
    }

    Ok(false)
}


fn main() {
    let rt = tokio::runtime::Runtime::new().unwrap();

    let resolver = match TokioAsyncResolver::tokio(ResolverConfig::default(), ResolverOpts::default()) {
        Ok(resolver) => resolver,
        Err(e) => {
            println!("Failed to create DNS resolver: {}", e);
            return;
        }
    };

    // Define the domain_url and the expected record
    let domain_url = "https://rotko.net";

    // no match
    //let expected_record = "e747830ab59ba99d4817ff11291811e6";

    // match
    let expected_record = "protonmail-verification=5efb90a51528f16d9ae4a23dd5faa9d5fa0a9221";

    match rt.block_on(check_txt_record(&resolver, domain_url, expected_record)) {
        Ok(true) => println!("Record found!"),
        Ok(false) => println!("Record not found."),
        Err(e) => println!("Error: {}", e),
    }
}


