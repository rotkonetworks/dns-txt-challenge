use clap::{App, Arg};
use std::error::Error;
use std::fmt;
use trust_dns_resolver::TokioAsyncResolver;
use trust_dns_resolver::config::{ResolverConfig, ResolverOpts};
use trust_dns_resolver::error::ResolveError;
// https://docs.rs/trust-dns-proto/latest/trust_dns_proto/
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
    let matches = App::new("DNS TXT Record Checker")
        .version("0.1.0")
        .about("Checks if a specific TXT record exists for a given domain")
        .arg(
            Arg::new("domain")
                .short('d')
                .long("domain")
                .value_name("DOMAIN")
                .help("The domain to check")
                .required(true)
                .takes_value(true),
        )
        .arg(
            Arg::new("record")
                .short('r')
                .long("record")
                .value_name("RECORD")
                .help("The TXT record to look for")
                .required(true)
                .takes_value(true),
        )
        .get_matches();

    let domain_url = matches.value_of("domain").unwrap();
    let expected_record = matches.value_of("record").unwrap();

    let rt = tokio::runtime::Runtime::new().unwrap();

    let resolver = match TokioAsyncResolver::tokio(ResolverConfig::default(), ResolverOpts::default()) {
        Ok(resolver) => resolver,
        Err(e) => {
            println!("Failed to create DNS resolver: {}", e);
            return;
        }
    };

    match rt.block_on(check_txt_record(&resolver, domain_url, expected_record)) {
        Ok(true) => println!("Record found!"),
        Ok(false) => println!("Record not found."),
        Err(e) => println!("Error: {}", e),
    }
}
