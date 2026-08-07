//! MAC address vendor lookup.
//!
//! A curated set of prefixes common on home networks is compiled in, so the
//! tool identifies most devices with no external data. Point
//! `discovery.oui_file` at the full IEEE `oui.csv` for exhaustive coverage.

use std::collections::HashMap;
use std::path::Path;

/// (OUI prefix without separators, vendor name)
const BUILTIN: &[(&str, &str)] = &[
    // Raspberry Pi
    ("B827EB", "Raspberry Pi Foundation"),
    ("DCA632", "Raspberry Pi Trading"),
    ("E45F01", "Raspberry Pi Trading"),
    ("D83ADD", "Raspberry Pi Trading"),
    ("2CCF67", "Raspberry Pi Trading"),
    ("88A29E", "Raspberry Pi Ltd"),
    // Apple
    ("F0D1A9", "Apple"),
    ("A85C2C", "Apple"),
    ("3C0754", "Apple"),
    ("D02598", "Apple"),
    ("AC87A3", "Apple"),
    ("8C8590", "Apple"),
    ("F80377", "Apple"),
    ("6C4008", "Apple"),
    ("A4B197", "Apple"),
    ("DC2B2A", "Apple"),
    ("E0B9BA", "Apple"),
    ("F0DBF8", "Apple"),
    ("04D3CF", "Apple"),
    ("BC926B", "Apple"),
    ("C82A14", "Apple"),
    // Samsung
    ("E8508B", "Samsung Electronics"),
    ("F409D8", "Samsung Electronics"),
    ("5CF6DC", "Samsung Electronics"),
    ("8C7712", "Samsung Electronics"),
    ("34BE00", "Samsung Electronics"),
    ("D0176A", "Samsung Electronics"),
    ("2C598A", "Samsung Electronics"),
    ("C0BDD1", "Samsung Electronics"),
    // Google / Nest
    ("F4F5D8", "Google"),
    ("F4F5E8", "Google"),
    ("3C5AB4", "Google"),
    ("DA A1 19", "Google"),
    ("1CF29A", "Google"),
    ("54600D", "Google Nest"),
    ("18B430", "Google Nest"),
    // Amazon
    ("F0272D", "Amazon Technologies"),
    ("44650D", "Amazon Technologies"),
    ("68375A", "Amazon Technologies"),
    ("A002DC", "Amazon Technologies"),
    ("FCA183", "Amazon Technologies"),
    ("74C246", "Amazon Technologies"),
    ("50DCE7", "Amazon Technologies"),
    // Intel (laptops/NICs)
    ("001B21", "Intel"),
    ("3C9709", "Intel"),
    ("94659C", "Intel"),
    ("A0A8CD", "Intel"),
    ("8CC681", "Intel"),
    ("E4A471", "Intel"),
    ("7C7A91", "Intel"),
    // Espressif (ESP8266/ESP32 - most DIY IoT)
    ("240AC4", "Espressif (ESP32)"),
    ("2462AB", "Espressif (ESP32)"),
    ("30AEA4", "Espressif (ESP32)"),
    ("3C71BF", "Espressif (ESP32)"),
    ("807D3A", "Espressif (ESP32)"),
    ("A4CF12", "Espressif (ESP32)"),
    ("B4E62D", "Espressif (ESP32)"),
    ("CC50E3", "Espressif (ESP32)"),
    ("D8A01D", "Espressif (ESP32)"),
    ("EC FA BC", "Espressif (ESP32)"),
    ("5CCF7F", "Espressif (ESP8266)"),
    ("18FE34", "Espressif (ESP8266)"),
    // TP-Link
    ("50C7BF", "TP-Link"),
    ("A42BB0", "TP-Link"),
    ("C46E1F", "TP-Link"),
    ("14CC20", "TP-Link"),
    ("6466B3", "TP-Link"),
    ("9C5322", "TP-Link"),
    ("003192", "TP-Link"),
    // Netgear
    ("A040A0", "Netgear"),
    ("204E7F", "Netgear"),
    ("9CD36D", "Netgear"),
    ("C40415", "Netgear"),
    // D-Link / Asus / Linksys
    ("1CBDB9", "D-Link"),
    ("14D64D", "D-Link"),
    ("2C4D54", "ASUSTek"),
    ("1C872C", "ASUSTek"),
    ("AC220B", "ASUSTek"),
    ("48F8B3", "Linksys"),
    ("C0561D", "Linksys"),
    // Xiaomi
    ("64B473", "Xiaomi"),
    ("F8A45F", "Xiaomi"),
    ("286C07", "Xiaomi"),
    ("78110F", "Xiaomi"),
    ("50EC50", "Xiaomi"),
    // Huawei
    ("00E0FC", "Huawei"),
    ("240995", "Huawei"),
    ("48D539", "Huawei"),
    ("781DBA", "Huawei"),
    // OnePlus / Oppo / Vivo / Realme
    ("64A2F9", "OnePlus"),
    ("C0EEFB", "OnePlus"),
    ("94652D", "OnePlus"),
    ("D0C5D3", "Oppo"),
    ("2CF0A2", "Vivo"),
    // Sonos / Roku / smart TV
    ("5CAAFD", "Sonos"),
    ("949F3E", "Sonos"),
    ("B8E937", "Sonos"),
    ("B0A737", "Roku"),
    ("CC6DA0", "Roku"),
    ("D83134", "Roku"),
    ("C8D083", "Vizio"),
    ("74E1B6", "LG Electronics"),
    ("A816B2", "LG Electronics"),
    ("2013E0", "Sony"),
    ("FCF152", "Sony"),
    // Philips Hue / IoT hubs
    ("001788", "Philips Hue"),
    ("ECB5FA", "Philips Hue"),
    // Ubiquiti / MikroTik / Cisco (prosumer networking)
    ("245A4C", "Ubiquiti"),
    ("788A20", "Ubiquiti"),
    ("FC ECDA", "Ubiquiti"),
    ("74ACB9", "Ubiquiti"),
    ("4C5E0C", "Routerboard (MikroTik)"),
    ("E48D8C", "Routerboard (MikroTik)"),
    ("6C3B6B", "Routerboard (MikroTik)"),
    ("001A2B", "Cisco"),
    ("F4CFE2", "Cisco"),
    // Printers
    ("3CD92B", "HP"),
    ("9CB6D0", "HP"),
    ("002673", "Brother"),
    ("008077", "Brother"),
    ("00000E", "Canon"),
    ("2477 03", "Epson"),
    // Virtualisation / containers, handy when testing
    ("000C29", "VMware"),
    ("005056", "VMware"),
    ("080027", "VirtualBox"),
    ("525400", "QEMU/KVM"),
    ("02420A", "Docker"),
    // Misc consumer
    ("B0BE76", "Belkin"),
    ("EC1A59", "Belkin/Wemo"),
    ("6038E0", "Belkin"),
    ("001E8F", "Canon"),
    ("00248C", "ASUSTek"),
    ("485D36", "Amazon eero"),
    ("F8BBBF", "Nintendo"),
    ("98B6E9", "Nintendo"),
    ("0017AB", "Nintendo"),
    ("7CBB8A", "Nintendo"),
    ("BC60A7", "Sony PlayStation"),
    ("F8461C", "Sony PlayStation"),
    ("000D3A", "Microsoft"),
    ("7C1E52", "Microsoft"),
    ("60455E", "Microsoft Xbox"),
];

#[derive(Debug, Default)]
pub struct OuiDb {
    map: HashMap<String, String>,
}

impl OuiDb {
    pub fn new() -> Self {
        let mut map = HashMap::with_capacity(BUILTIN.len());
        for (prefix, vendor) in BUILTIN {
            // Tolerate spaces in the table above so it stays easy to edit.
            let key: String = prefix
                .chars()
                .filter(|c| c.is_ascii_hexdigit())
                .flat_map(|c| c.to_uppercase())
                .collect();
            if key.len() == 6 {
                map.insert(key, (*vendor).to_string());
            }
        }
        Self { map }
    }

    /// Merge the IEEE `oui.csv` if present. Format:
    /// `Registry,Assignment,Organization Name,Organization Address`
    pub fn load_ieee_csv(&mut self, path: &Path) -> anyhow::Result<usize> {
        let text = std::fs::read_to_string(path)?;
        let mut added = 0;
        for line in text.lines().skip(1) {
            // Organization names can contain commas inside quotes; we only need
            // the first two plain fields plus whatever follows.
            let mut fields = line.splitn(4, ',');
            let _registry = fields.next();
            let Some(assignment) = fields.next() else {
                continue;
            };
            let Some(org) = fields.next() else { continue };

            let key: String = assignment
                .chars()
                .filter(|c| c.is_ascii_hexdigit())
                .flat_map(|c| c.to_uppercase())
                .collect();
            if key.len() != 6 {
                continue;
            }
            let org = org.trim().trim_matches('"').trim();
            if org.is_empty() {
                continue;
            }
            // Built-in names are friendlier ("Raspberry Pi" vs the registrant's
            // legal name), so only fill gaps.
            self.map.entry(key).or_insert_with(|| org.to_string());
            added += 1;
        }
        Ok(added)
    }

    pub fn len(&self) -> usize {
        self.map.len()
    }

    /// Look up the vendor for a MAC in any common notation.
    pub fn lookup(&self, mac: &str) -> Option<&str> {
        let hex: String = mac
            .chars()
            .filter(|c| c.is_ascii_hexdigit())
            .flat_map(|c| c.to_uppercase())
            .collect();
        if hex.len() < 6 {
            return None;
        }
        self.map.get(&hex[..6]).map(|s| s.as_str())
    }
}

/// True when the MAC is locally administered, which on a modern phone or
/// laptop almost always means the OS is randomising it for privacy. Such a
/// MAC is not a stable device identity and has no real vendor.
pub fn is_randomized(mac: &str) -> bool {
    let hex: String = mac.chars().filter(|c| c.is_ascii_hexdigit()).collect();
    if hex.len() < 2 {
        return false;
    }
    match u8::from_str_radix(&hex[..2], 16) {
        // Bit 1 of the first octet is the "locally administered" flag.
        Ok(first) => first & 0b0000_0010 != 0,
        Err(_) => false,
    }
}

/// Canonical lowercase colon-separated form, or None if it isn't a MAC.
pub fn normalize(mac: &str) -> Option<String> {
    let hex: String = mac.chars().filter(|c| c.is_ascii_hexdigit()).collect();
    if hex.len() != 12 {
        return None;
    }
    // All-zero MACs appear in incomplete ARP entries; they identify nothing.
    if hex.chars().all(|c| c == '0') {
        return None;
    }
    let lower = hex.to_ascii_lowercase();
    let pairs: Vec<String> = (0..6)
        .map(|i| lower[i * 2..i * 2 + 2].to_string())
        .collect();
    Some(pairs.join(":"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn finds_builtin_vendors() {
        let db = OuiDb::new();
        assert_eq!(
            db.lookup("b8:27:eb:11:22:33"),
            Some("Raspberry Pi Foundation")
        );
        assert_eq!(db.lookup("B827EB112233"), Some("Raspberry Pi Foundation"));
        assert_eq!(db.lookup("5c-cf-7f-aa-bb-cc"), Some("Espressif (ESP8266)"));
        assert_eq!(db.lookup("ff:ff:ff:ff:ff:ff"), None);
    }

    #[test]
    fn detects_randomized_macs() {
        // Second-lowest bit of the first octet set -> locally administered.
        assert!(is_randomized("06:11:22:33:44:55"));
        assert!(is_randomized("a2:11:22:33:44:55"));
        assert!(!is_randomized("b8:27:eb:11:22:33"));
        assert!(!is_randomized("00:0c:29:aa:bb:cc"));
    }

    #[test]
    fn normalizes_notations() {
        assert_eq!(
            normalize("B8-27-EB-11-22-33").as_deref(),
            Some("b8:27:eb:11:22:33")
        );
        assert_eq!(
            normalize("b827eb112233").as_deref(),
            Some("b8:27:eb:11:22:33")
        );
        assert_eq!(normalize("00:00:00:00:00:00"), None);
        assert_eq!(normalize("not-a-mac"), None);
    }
}
