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

#[derive(Clone, Debug)]
pub struct Server {
    pub region: ServerRegion,
    pub name: &'static str,
    pub hint: &'static str,
    pub addresses: Vec<String>,
}

pub fn default_servers() -> Vec<Server> {
    vec![
        server(
            ServerRegion::Brazil,
            "Brazil",
            "GBR1",
            include_str!("../../data/servers/brazil.txt"),
        ),
        server(
            ServerRegion::Australia,
            "Australia",
            "SYD2",
            include_str!("../../data/servers/australia.txt"),
        ),
        server(
            ServerRegion::UsaCentral,
            "US Central",
            "ORD1",
            include_str!("../../data/servers/usa_central.txt"),
        ),
        server(
            ServerRegion::UsaEast,
            "US East",
            "GUE4",
            include_str!("../../data/servers/usa_east.txt"),
        ),
        server(
            ServerRegion::UsaWest,
            "US West",
            "LAX/LAS",
            include_str!("../../data/servers/usa_west.txt"),
        ),
        server(
            ServerRegion::Europe,
            "Europe",
            "EU",
            include_str!("../../data/servers/europe.txt"),
        ),
        server(
            ServerRegion::MiddleEast,
            "Middle East",
            "ME",
            include_str!("../../data/servers/middle_east.txt"),
        ),
        server(
            ServerRegion::AsiaJapan,
            "Asia Japan",
            "GTK1",
            include_str!("../../data/servers/asia_japan.txt"),
        ),
        server(
            ServerRegion::AsiaKorea,
            "Asia Korea",
            "ICN1",
            include_str!("../../data/servers/asia_korea.txt"),
        ),
        server(
            ServerRegion::AsiaSingapore,
            "Asia Singapore",
            "GSG1",
            include_str!("../../data/servers/asia_singapore.txt"),
        ),
        server(
            ServerRegion::AsiaTaiwan,
            "Asia Taiwan",
            "TPE1",
            include_str!("../../data/servers/asia_taiwan.txt"),
        ),
    ]
}

fn server(region: ServerRegion, name: &'static str, hint: &'static str, raw: &str) -> Server {
    let addresses = crate::core::address::parse_address_list(raw).unwrap_or_else(|error| {
        panic!(
            "invalid IP list in {name}: {} ({})",
            error.token, error.reason
        )
    });

    Server {
        region,
        name,
        hint,
        addresses,
    }
}

#[cfg(test)]
mod tests {
    use super::default_servers;

    #[test]
    fn every_default_server_has_addresses() {
        for server in default_servers() {
            assert!(
                !server.addresses.is_empty(),
                "{} must have at least one address",
                server.name
            );
        }
    }
}
