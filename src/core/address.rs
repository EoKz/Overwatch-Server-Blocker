use std::collections::BTreeSet;
use std::net::IpAddr;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AddressParseError {
    pub token: String,
    pub reason: String,
}

impl AddressParseError {
    fn new(token: &str, reason: impl Into<String>) -> Self {
        Self {
            token: token.to_string(),
            reason: reason.into(),
        }
    }
}

pub fn parse_address_list(raw: &str) -> Result<Vec<String>, AddressParseError> {
    let mut seen = BTreeSet::new();
    let mut addresses = Vec::new();

    for line in raw.lines() {
        let line = line.split_once('#').map_or(line, |(value, _)| value);

        for token in line
            .split(',')
            .map(str::trim)
            .filter(|line| !line.is_empty())
        {
            let address = normalize_address(token)?;
            if seen.insert(address.clone()) {
                addresses.push(address);
            }
        }
    }

    Ok(addresses)
}

pub fn normalize_address(token: &str) -> Result<String, AddressParseError> {
    let token = token.trim();

    if token.is_empty() {
        return Err(AddressParseError::new(token, "empty address"));
    }

    if let Some((start, end)) = token.split_once('-') {
        return normalize_range(token, start.trim(), end.trim());
    }

    if let Some((ip, prefix)) = token.split_once('/') {
        return normalize_cidr(token, ip.trim(), prefix.trim());
    }

    token
        .parse::<IpAddr>()
        .map(|ip| ip.to_string())
        .map_err(|_| AddressParseError::new(token, "invalid IP"))
}

fn normalize_range(original: &str, start: &str, end: &str) -> Result<String, AddressParseError> {
    let start_ip = start
        .parse::<IpAddr>()
        .map_err(|_| AddressParseError::new(original, "invalid range start"))?;
    let end_ip = end
        .parse::<IpAddr>()
        .map_err(|_| AddressParseError::new(original, "invalid range end"))?;

    match (start_ip, end_ip) {
        (IpAddr::V4(start), IpAddr::V4(end)) if start <= end => Ok(format!("{start}-{end}")),
        (IpAddr::V6(start), IpAddr::V6(end)) if start <= end => Ok(format!("{start}-{end}")),
        (IpAddr::V4(_), IpAddr::V4(_)) | (IpAddr::V6(_), IpAddr::V6(_)) => {
            Err(AddressParseError::new(original, "reversed range"))
        }
        _ => Err(AddressParseError::new(
            original,
            "range mixes IPv4 and IPv6",
        )),
    }
}

fn normalize_cidr(original: &str, ip: &str, prefix: &str) -> Result<String, AddressParseError> {
    let ip = ip
        .parse::<IpAddr>()
        .map_err(|_| AddressParseError::new(original, "invalid CIDR IP"))?;
    let prefix = prefix
        .parse::<u8>()
        .map_err(|_| AddressParseError::new(original, "invalid CIDR prefix"))?;

    let max_prefix = match ip {
        IpAddr::V4(_) => 32,
        IpAddr::V6(_) => 128,
    };

    if prefix > max_prefix {
        return Err(AddressParseError::new(
            original,
            format!("CIDR prefix is greater than {max_prefix}"),
        ));
    }

    Ok(format!("{ip}/{prefix}"))
}

#[cfg(test)]
mod tests {
    use super::{normalize_address, parse_address_list};

    #[test]
    fn parses_ip_cidr_and_range() {
        let parsed = parse_address_list(
            "# one IP, CIDR, or range per line\n\
             34.95.128.0/17\n\
             37.244.42.0-37.244.42.255\n\
             2600:1900:40f0::/44 # Brazil IPv6\n\
             8.8.8.8",
        )
        .expect("valid addresses");

        assert_eq!(
            parsed,
            vec![
                "34.95.128.0/17",
                "37.244.42.0-37.244.42.255",
                "2600:1900:40f0::/44",
                "8.8.8.8"
            ]
        );
    }

    #[test]
    fn rejects_invalid_ranges() {
        let error = normalize_address("10.0.0.10-10.0.0.1").expect_err("must reject");
        assert!(error.reason.contains("reversed"));
    }

    #[test]
    fn deduplicates_without_reordering_first_occurrence() {
        let parsed = parse_address_list("8.8.8.8\n1.1.1.1\n8.8.8.8").expect("valid");
        assert_eq!(parsed, vec!["8.8.8.8", "1.1.1.1"]);
    }
}
