use clap::{App, Arg};
use dns_txt_checker::{TxtRecordError, check_txt_record};
use trust_dns_resolver::TokioAsyncResolver;
use trust_dns_resolver::config::{ResolverConfig, ResolverOpts};

#[tokio::main]
async fn main() {
    let matches = App::new(env!("CARGO_PKG_NAME"))
        .version(env!("CARGO_PKG_VERSION"))
        .author(env!("CARGO_PKG_AUTHORS"))
        .about(env!("CARGO_PKG_DESCRIPTION"))
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

    let resolver = match TokioAsyncResolver::tokio(ResolverConfig::default(), ResolverOpts::default()) {
        Ok(resolver) => resolver,
        Err(e) => {
            println!("Failed to create DNS resolver: {}", e);
            return;
        }
    };
    match check_txt_record(&resolver, domain_url, expected_record).await {
        Ok(true) => println!("Record found!"),
        Ok(false) => println!("Record not found."),
        Err(e) => match e {
            TxtRecordError::UrlParseError(err) => {
                println!("URL parse error: {}", err);
            }
            TxtRecordError::NoDomainInUrl => {
                println!("No domain found in URL");
            }
            TxtRecordError::DnsResolutionError(err) => {
                println!("DNS resolution error: {}", err);
            }
        },
    }
}
