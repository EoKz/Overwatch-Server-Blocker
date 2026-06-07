#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum ServerRegion {
    Brazil,
    Australia,
    UsaCentral,
    UsaEast,
    UsaWest,
    Europe,
    MiddleEast,
    AsiaJapan,
    AsiaKorea,
    AsiaSingapore,
    AsiaTaiwan,
}

impl ServerRegion {
    pub fn id(self) -> &'static str {
        match self {
            Self::Brazil => "brazil",
            Self::Australia => "australia",
            Self::UsaCentral => "us_central",
            Self::UsaEast => "us_east",
            Self::UsaWest => "us_west",
            Self::Europe => "europe",
            Self::MiddleEast => "middle_east",
            Self::AsiaJapan => "asia_japan",
            Self::AsiaKorea => "asia_korea",
            Self::AsiaSingapore => "asia_singapore",
            Self::AsiaTaiwan => "asia_taiwan",
        }
    }

    pub fn from_id(value: &str) -> Option<Self> {
        match normalized_region_id(value).as_str() {
            "brazil" | "brasil" => Some(Self::Brazil),
            "australia" => Some(Self::Australia),
            "us_central" | "usa_central" | "eua_central" => Some(Self::UsaCentral),
            "us_east" | "usa_east" | "eua_east" => Some(Self::UsaEast),
            "us_west" | "usa_west" | "eua_west" => Some(Self::UsaWest),
            "europe" | "europa" => Some(Self::Europe),
            "middle_east" | "oriente_medio" => Some(Self::MiddleEast),
            "asia_japan" => Some(Self::AsiaJapan),
            "asia_korea" => Some(Self::AsiaKorea),
            "asia_singapore" => Some(Self::AsiaSingapore),
            "asia_taiwan" => Some(Self::AsiaTaiwan),
            _ => None,
        }
    }
}

fn normalized_region_id(value: &str) -> String {
    value.trim().to_ascii_lowercase().replace([' ', '-'], "_")
}

#[derive(Clone, Debug)]
pub struct ServerGroup {
    pub region: ServerRegion,
    pub name: &'static str,
    pub hint: &'static str,
    pub targets: Vec<ServerTarget>,
}

#[derive(Clone, Debug)]
pub struct ServerTarget {
    pub id: &'static str,
    pub label: &'static str,
    pub provider: ServerProvider,
    pub identifier: &'static str,
    pub confidence: TargetConfidence,
    pub addresses: Vec<String>,
    pub probe_ips: Vec<&'static str>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ServerProvider {
    Blizzard,
    GoogleCloud,
    #[allow(dead_code)]
    Aws,
    Community,
}

impl ServerProvider {
    pub fn label(self) -> &'static str {
        match self {
            Self::Blizzard => "Blizzard",
            Self::GoogleCloud => "Google Cloud",
            Self::Aws => "AWS",
            Self::Community => "Community",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TargetConfidence {
    KnownOw,
    ProviderRegion,
    Community,
}

impl TargetConfidence {
    pub fn label(self) -> &'static str {
        match self {
            Self::KnownOw => "Known OW/Blizzard",
            Self::ProviderRegion => "Provider region",
            Self::Community => "Community",
        }
    }
}

impl ServerGroup {
    pub fn addresses(&self) -> Vec<String> {
        dedupe_addresses(
            self.targets
                .iter()
                .flat_map(|target| target.addresses.iter()),
        )
    }

    pub fn target_count(&self) -> usize {
        self.targets.len()
    }
}

impl ServerTarget {
    pub fn address_count(&self) -> usize {
        self.addresses.len()
    }
}

pub fn default_servers() -> Vec<ServerGroup> {
    vec![
        group(
            ServerRegion::Brazil,
            "Brazil",
            "GBR1",
            vec![target(
                "google:southamerica-east1",
                "Brazil, Sao Paulo",
                ServerProvider::GoogleCloud,
                "southamerica-east1",
                TargetConfidence::ProviderRegion,
                include_str!("../../data/servers/brazil.txt"),
                &["34.95.128.1", "35.198.0.1"],
            )],
        ),
        group(
            ServerRegion::Australia,
            "Australia",
            "SYD2",
            vec![
                target_excluding(
                    "google:australia-southeast1",
                    "Australia, Sydney",
                    ServerProvider::GoogleCloud,
                    "australia-southeast1",
                    TargetConfidence::ProviderRegion,
                    (
                        include_str!("../../data/servers/australia.txt"),
                        "158.115.196.0/23\n37.244.42.0-37.244.42.255",
                    ),
                    &["34.87.192.1", "35.189.0.1"],
                ),
                target(
                    "blizzard:syd2",
                    "Australia, Sydney",
                    ServerProvider::Blizzard,
                    "SYD2",
                    TargetConfidence::KnownOw,
                    "158.115.196.0/23",
                    &["158.115.196.1"],
                ),
                target(
                    "community:aus",
                    "Australia community ranges",
                    ServerProvider::Community,
                    "AUS",
                    TargetConfidence::Community,
                    "37.244.42.0-37.244.42.255",
                    &["37.244.42.1"],
                ),
            ],
        ),
        group(
            ServerRegion::UsaCentral,
            "US Central",
            "ORD1",
            vec![
                target_excluding(
                    "google:us-central1",
                    "United States, Iowa",
                    ServerProvider::GoogleCloud,
                    "us-central1",
                    TargetConfidence::ProviderRegion,
                    (
                        include_str!("../../data/servers/usa_central.txt"),
                        "64.224.0.0/21\n24.105.40.0/21",
                    ),
                    &["34.66.0.1", "35.184.0.1"],
                ),
                target(
                    "blizzard:ord1",
                    "United States, Chicago",
                    ServerProvider::Blizzard,
                    "ORD1",
                    TargetConfidence::KnownOw,
                    "64.224.0.0/21\n24.105.40.0/21",
                    &["64.224.0.1", "24.105.40.1"],
                ),
            ],
        ),
        group(
            ServerRegion::UsaEast,
            "US East",
            "GUE4",
            vec![target(
                "google:us-east4",
                "United States, Virginia",
                ServerProvider::GoogleCloud,
                "us-east4",
                TargetConfidence::ProviderRegion,
                include_str!("../../data/servers/usa_east.txt"),
                &["34.86.0.1", "35.245.0.1"],
            )],
        ),
        group(
            ServerRegion::UsaWest,
            "US West",
            "LAX/LAS",
            vec![
                target_excluding(
                    "google:us-west",
                    "United States, Western Google regions",
                    ServerProvider::GoogleCloud,
                    "us-west1/us-west2",
                    TargetConfidence::ProviderRegion,
                    (
                        include_str!("../../data/servers/usa_west.txt"),
                        "64.224.24.0/23\n24.105.8.0-24.105.15.255",
                    ),
                    &["34.82.0.1", "35.185.192.1"],
                ),
                target(
                    "blizzard:las1",
                    "United States, Nevada",
                    ServerProvider::Blizzard,
                    "LAS1",
                    TargetConfidence::KnownOw,
                    "64.224.24.0/23",
                    &["64.224.24.1"],
                ),
                target(
                    "community:lax",
                    "United States, Los Angeles",
                    ServerProvider::Community,
                    "LAX",
                    TargetConfidence::Community,
                    "24.105.8.0-24.105.15.255",
                    &["24.105.8.1"],
                ),
            ],
        ),
        group(
            ServerRegion::Europe,
            "Europe",
            "EU",
            vec![
                target_excluding(
                    "google:europe",
                    "Europe Google regions",
                    ServerProvider::GoogleCloud,
                    "europe-*",
                    TargetConfidence::ProviderRegion,
                    (
                        include_str!("../../data/servers/europe.txt"),
                        "64.224.26.0/23\n5.42.168.0-5.42.175.255\n5.42.184.0-5.42.191.255",
                    ),
                    &["34.76.0.1", "35.195.0.1"],
                ),
                target(
                    "blizzard:ams1",
                    "Netherlands, Amsterdam",
                    ServerProvider::Blizzard,
                    "AMS1",
                    TargetConfidence::KnownOw,
                    "64.224.26.0/23",
                    &["64.224.26.1"],
                ),
                target(
                    "community:eu",
                    "Europe community ranges",
                    ServerProvider::Community,
                    "EU",
                    TargetConfidence::Community,
                    "5.42.168.0-5.42.175.255\n5.42.184.0-5.42.191.255",
                    &["5.42.168.1"],
                ),
            ],
        ),
        group(
            ServerRegion::MiddleEast,
            "Middle East",
            "ME",
            vec![target(
                "google:me-central1",
                "Qatar, Doha",
                ServerProvider::GoogleCloud,
                "me-central1",
                TargetConfidence::ProviderRegion,
                include_str!("../../data/servers/middle_east.txt"),
                &["34.18.0.1", "35.246.192.1"],
            )],
        ),
        group(
            ServerRegion::AsiaJapan,
            "Asia Japan",
            "GTK1",
            vec![target(
                "google:asia-northeast1",
                "Japan, Tokyo",
                ServerProvider::GoogleCloud,
                "asia-northeast1",
                TargetConfidence::ProviderRegion,
                include_str!("../../data/servers/asia_japan.txt"),
                &["34.84.0.1", "35.200.0.1"],
            )],
        ),
        group(
            ServerRegion::AsiaKorea,
            "Asia Korea",
            "ICN1",
            vec![
                target_excluding(
                    "google:asia-northeast3",
                    "South Korea, Seoul",
                    ServerProvider::GoogleCloud,
                    "asia-northeast3",
                    TargetConfidence::ProviderRegion,
                    (
                        include_str!("../../data/servers/asia_korea.txt"),
                        "110.45.208.0/24\n117.52.6.0/24\n117.52.26.0/23\n117.52.28.0/23\n117.52.33.0/24\n117.52.34.0/23\n117.52.36.0/23\n121.254.137.0/24\n121.254.206.0/23\n121.254.218.0/24\n182.162.31.0/24",
                    ),
                    &["34.64.0.1", "35.216.0.1"],
                ),
                target(
                    "blizzard:icn1",
                    "South Korea, Incheon",
                    ServerProvider::Blizzard,
                    "ICN1",
                    TargetConfidence::KnownOw,
                    "110.45.208.0/24\n117.52.6.0/24\n117.52.26.0/23\n117.52.28.0/23\n117.52.33.0/24\n117.52.34.0/23\n117.52.36.0/23\n121.254.137.0/24\n121.254.206.0/23\n121.254.218.0/24\n182.162.31.0/24",
                    &["110.45.208.1", "182.162.31.1"],
                ),
            ],
        ),
        group(
            ServerRegion::AsiaSingapore,
            "Asia Singapore",
            "GSG1",
            vec![target(
                "google:asia-southeast1",
                "Singapore, Jurong West",
                ServerProvider::GoogleCloud,
                "asia-southeast1",
                TargetConfidence::ProviderRegion,
                include_str!("../../data/servers/asia_singapore.txt"),
                &["34.87.0.1", "35.198.192.1"],
            )],
        ),
        group(
            ServerRegion::AsiaTaiwan,
            "Asia Taiwan",
            "TPE1",
            vec![
                target_excluding(
                    "google:asia-east1",
                    "Taiwan, Changhua County",
                    ServerProvider::GoogleCloud,
                    "asia-east1",
                    TargetConfidence::ProviderRegion,
                    (
                        include_str!("../../data/servers/asia_taiwan.txt"),
                        "5.42.160.0/22\n5.42.164.0/22",
                    ),
                    &["34.80.0.1", "35.194.128.1"],
                ),
                target(
                    "blizzard:tpe1",
                    "Taiwan, Taipei",
                    ServerProvider::Blizzard,
                    "TPE1",
                    TargetConfidence::KnownOw,
                    "5.42.160.0/22\n5.42.164.0/22",
                    &["5.42.160.1"],
                ),
            ],
        ),
    ]
}

fn group(
    region: ServerRegion,
    name: &'static str,
    hint: &'static str,
    targets: Vec<ServerTarget>,
) -> ServerGroup {
    ServerGroup {
        region,
        name,
        hint,
        targets,
    }
}

fn target(
    id: &'static str,
    label: &'static str,
    provider: ServerProvider,
    identifier: &'static str,
    confidence: TargetConfidence,
    raw: &str,
    probe_ips: &[&'static str],
) -> ServerTarget {
    let addresses = crate::core::address::parse_address_list(raw).unwrap_or_else(|error| {
        panic!(
            "invalid IP list in {id}: {} ({})",
            error.token, error.reason
        )
    });

    target_from_addresses(
        id, label, provider, identifier, confidence, addresses, probe_ips,
    )
}

fn target_excluding(
    id: &'static str,
    label: &'static str,
    provider: ServerProvider,
    identifier: &'static str,
    confidence: TargetConfidence,
    raw_and_excluded: (&str, &str),
    probe_ips: &[&'static str],
) -> ServerTarget {
    let (raw, excluded_raw) = raw_and_excluded;
    let addresses = crate::core::address::parse_address_list(raw).unwrap_or_else(|error| {
        panic!(
            "invalid IP list in {id}: {} ({})",
            error.token, error.reason
        )
    });
    let excluded: std::collections::BTreeSet<String> =
        crate::core::address::parse_address_list(excluded_raw)
            .unwrap_or_else(|error| {
                panic!(
                    "invalid excluded IP list in {id}: {} ({})",
                    error.token, error.reason
                )
            })
            .into_iter()
            .collect();
    let addresses = addresses
        .into_iter()
        .filter(|address| !excluded.contains(address))
        .collect();

    target_from_addresses(
        id, label, provider, identifier, confidence, addresses, probe_ips,
    )
}

fn target_from_addresses(
    id: &'static str,
    label: &'static str,
    provider: ServerProvider,
    identifier: &'static str,
    confidence: TargetConfidence,
    addresses: Vec<String>,
    probe_ips: &[&'static str],
) -> ServerTarget {
    ServerTarget {
        id,
        label,
        provider,
        identifier,
        confidence,
        addresses,
        probe_ips: probe_ips.to_vec(),
    }
}

fn dedupe_addresses<'a>(addresses: impl Iterator<Item = &'a String>) -> Vec<String> {
    let mut seen = std::collections::BTreeSet::new();
    let mut deduped = Vec::new();

    for address in addresses {
        if seen.insert(address.clone()) {
            deduped.push(address.clone());
        }
    }

    deduped
}

#[cfg(test)]
mod tests {
    use super::{ServerRegion, default_servers};

    #[test]
    fn every_default_server_has_addresses() {
        for group in default_servers() {
            assert!(
                !group.addresses().is_empty(),
                "{} must have at least one address",
                group.name
            );

            for target in &group.targets {
                assert!(
                    !target.addresses.is_empty(),
                    "{} must have at least one address",
                    target.id
                );
            }
        }
    }

    #[test]
    fn every_target_has_a_stable_unique_id() {
        let mut ids = std::collections::BTreeSet::new();

        for group in default_servers() {
            for target in group.targets {
                assert!(
                    target.id.contains(':'),
                    "{} should include provider",
                    target.id
                );
                assert!(ids.insert(target.id), "{} must be unique", target.id);
            }
        }
    }

    #[test]
    fn region_ids_roundtrip_and_accept_legacy_names() {
        for server in default_servers() {
            assert_eq!(
                ServerRegion::from_id(server.region.id()),
                Some(server.region)
            );
        }

        assert_eq!(ServerRegion::from_id("Brasil"), Some(ServerRegion::Brazil));
        assert_eq!(
            ServerRegion::from_id("EUA Central"),
            Some(ServerRegion::UsaCentral)
        );
    }
}
