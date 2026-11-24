// SPDX-License-Identifier: AGPL-3.0-or-later
// Liest die oeffentlichen Registrierungsdaten der Regionalregistrare (RIPE, APNIC, AFRINIC, LACNIC) und
// schreibt die Adressbereiche, die nach Netzname und Beschreibung Hosting sind, als CIDR-Liste.
// Aufruf: rirbuild <ordner mit den .gz-Dateien> <ausgabedatei>
// RIR_SAMPLE=<datei>: schreibt jeden 200. Treffer mit Text zur Pruefung.
use flate2::read::MultiGzDecoder;
use regex::Regex;
use std::fs::{self, File};
use std::io::{BufRead, BufReader, BufWriter, Write};
use std::net::{Ipv4Addr, Ipv6Addr};
use std::path::PathBuf;

const STRONG: &str = r"(?i)\b(hosting|hoster|hosted|webhosting|vps|vds|vserver|dedicated[- ]servers?|virtual dedicated|dedicated hosting|dedicated vps|datacenter|datacentre|data[- ]cent(?:er|re)|colocation|co-location|colo|iaas|bare[- ]metal|virtual private|anonymi[sz]er|cloud|servers?|serverhost|cdn)\b";
const NEGATIVE: &str = r"(?i)\b(dsl|adsl|vdsl|ftth|fttx|fttb|broadband|cable|residential|customers?|subscribers?|dial-?up|mobile|wireless|gprs|lte|umts|[345]g|home|end[- ]user|dia|internet access|leased line|dynamic|wlan|wifi|hotspot|pppoe|dhcp|pool|telecom|telekom|telecommunications?|isp|internet service|school|university|college|government|ministry|hospital|bank)\b";
// Diese Woerter allein reichen nicht (zu viele Netze nennen "server" oder "cloud" nur nebenbei)
const WEAK: [&str; 4] = ["server", "servers", "cloud", "cdn"];

#[derive(Default)]
struct Object {
    range: Option<(u128, u128, u8)>,
    text: String,
    status: String,
}

fn parse_v4(text: &str) -> Option<u32> {
    // auch verkuerzt wie "200.1.2" bei LACNIC
    let parts: Vec<&str> = text.trim().split('.').collect();
    if parts.is_empty() || parts.len() > 4 {
        return None;
    }
    let mut octets = [0u8; 4];
    for (i, p) in parts.iter().enumerate() {
        octets[i] = p.parse().ok()?;
    }
    Some(u32::from(Ipv4Addr::from(octets)))
}

fn parse_inetnum(value: &str) -> Option<(u128, u128, u8)> {
    let value = value.trim();
    if let Some((a, b)) = value.split_once(" - ") {
        return Some((parse_v4(a)? as u128, parse_v4(b)? as u128, 4));
    }
    if let Some((a, len)) = value.split_once('/') {
        let start = parse_v4(a)? as u128;
        let len: u32 = len.trim().parse().ok()?;
        if len > 32 {
            return None;
        }
        let size = 1u128 << (32 - len);
        let base = start & !(size - 1);
        return Some((base, base + size - 1, 4));
    }
    None
}

fn parse_inet6num(value: &str) -> Option<(u128, u128, u8)> {
    let (a, len) = value.trim().split_once('/')?;
    let start = u128::from(a.trim().parse::<Ipv6Addr>().ok()?);
    let len: u32 = len.trim().parse().ok()?;
    if len > 128 {
        return None;
    }
    let size = if len == 0 { return None } else { 1u128 << (128 - len) };
    let base = start & !(size - 1);
    Some((base, base + size - 1, 6))
}

fn cidrs(start: u128, end: u128, version: u8, out: &mut Vec<String>) {
    let bits: u32 = if version == 4 { 32 } else { 128 };
    let mut cur = start;
    while cur <= end {
        let mut size_bits = if cur == 0 { bits } else { cur.trailing_zeros().min(bits) };
        while size_bits > 0 && cur + ((1u128 << size_bits) - 1) > end {
            size_bits -= 1;
        }
        let prefix = bits - size_bits;
        if version == 4 {
            out.push(format!("{}/{}", Ipv4Addr::from(cur as u32), prefix));
        } else {
            out.push(format!("{}/{}", Ipv6Addr::from(cur), prefix));
        }
        let step = 1u128 << size_bits;
        match cur.checked_add(step) {
            Some(next) if next > cur => cur = next,
            _ => break,
        }
    }
}

fn main() -> Result<(), String> {
    let mut args = std::env::args().skip(1);
    let dir = PathBuf::from(args.next().ok_or("usage: rirbuild <dir> <out>")?);
    let out_path = PathBuf::from(args.next().ok_or("usage: rirbuild <dir> <out>")?);
    let strong = Regex::new(STRONG).unwrap();
    let negative = Regex::new(NEGATIVE).unwrap();
    let mut sample = std::env::var("RIR_SAMPLE").ok().map(|p| BufWriter::new(File::create(p).unwrap()));

    let mut files: Vec<PathBuf> = fs::read_dir(&dir)
        .map_err(|e| e.to_string())?
        .filter_map(|e| e.ok().map(|e| e.path()))
        .filter(|p| p.extension().map_or(false, |x| x == "gz"))
        .collect();
    files.sort();

    let mut ranges: Vec<(u128, u128, u8)> = Vec::new();
    let (mut objects, mut matched, mut rejected) = (0u64, 0u64, 0u64);

    for file in &files {
        let reader = BufReader::new(MultiGzDecoder::new(File::open(file).map_err(|e| e.to_string())?));
        let name = file.file_name().unwrap().to_string_lossy().to_string();
        let mut current = Object::default();
        let mut file_objects = 0u64;
        let mut flush = |object: &mut Object, ranges: &mut Vec<(u128, u128, u8)>| {
            if let Some(range) = object.range {
                objects += 1;
                file_objects += 1;
                let text = object.text.as_str();
                let hit = strong.find_iter(text).map(|m| m.as_str().to_lowercase()).collect::<Vec<_>>();
                let strong_hit = hit.iter().any(|w| !WEAK.contains(&w.as_str()));
                let weak_only = !hit.is_empty() && !strong_hit;
                if strong_hit || weak_only && false {
                    if negative.is_match(text) {
                        rejected += 1;
                    } else {
                        matched += 1;
                        ranges.push(range);
                        if let Some(s) = sample.as_mut() {
                            if matched % 200 == 0 {
                                let _ = writeln!(s, "{}\t{}-{}\t{}", name, range.0, range.1, text.replace('\n', " | "));
                            }
                        }
                    }
                }
            }
            *object = Object::default();
        };
        for line in reader.split(b'\n') {
            let line = String::from_utf8_lossy(&line.map_err(|e| e.to_string())?).into_owned();
            let line = line.trim_end_matches('\r');
            if line.is_empty() {
                flush(&mut current, &mut ranges);
                continue;
            }
            if line.starts_with('#') || line.starts_with('%') {
                continue;
            }
            let Some((key, value)) = line.split_once(':') else { continue };
            let value = value.trim();
            match key {
                "inetnum" => current.range = parse_inetnum(value),
                "inet6num" => current.range = parse_inet6num(value),
                "netname" | "descr" | "owner" | "mnt-by" | "org-name" => {
                    current.text.push_str(value);
                    current.text.push('\n');
                }
                "status" => current.status = value.to_string(),
                _ => {}
            }
        }
        flush(&mut current, &mut ranges);
        eprintln!("{}: {} objects", name, file_objects);
    }

    // zusammenfuehren je Familie
    ranges.sort();
    let mut merged: Vec<(u128, u128, u8)> = Vec::new();
    for (s, e, v) in ranges {
        match merged.last_mut() {
            Some(last) if last.2 == v && s <= last.1.saturating_add(1) => last.1 = last.1.max(e),
            _ => merged.push((s, e, v)),
        }
    }
    let mut lines: Vec<String> = Vec::new();
    let mut v4_addresses: u128 = 0;
    for (s, e, v) in &merged {
        cidrs(*s, *e, *v, &mut lines);
        if *v == 4 {
            v4_addresses += e - s + 1;
        }
    }
    let mut writer = BufWriter::new(File::create(&out_path).map_err(|e| e.to_string())?);
    for line in &lines {
        writeln!(writer, "{line}").map_err(|e| e.to_string())?;
    }
    writer.flush().map_err(|e| e.to_string())?;
    eprintln!("objects {objects} matched {matched} rejected-by-negative {rejected}; ranges {} cidrs {} ipv4 addresses {}", merged.len(), lines.len(), v4_addresses);
    println!("cidrs {}", lines.len());
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn range_becomes_cidrs() {
        let (s, e, v) = parse_inetnum("10.0.0.0 - 10.0.0.255").unwrap();
        let mut out = Vec::new();
        cidrs(s, e, v, &mut out);
        assert_eq!(out, vec!["10.0.0.0/24"]);
        let (s, e, v) = parse_inetnum("10.0.0.0 - 10.0.1.127").unwrap();
        let mut out = Vec::new();
        cidrs(s, e, v, &mut out);
        assert_eq!(out, vec!["10.0.0.0/24", "10.0.1.0/25"]);
    }

    #[test]
    fn short_lacnic_form_and_cidr() {
        assert_eq!(parse_inetnum("200.1.2/24").unwrap().0, 0xC8010200);
        let (s, e, _) = parse_inet6num("2001:db8::/32").unwrap();
        assert_eq!(e - s + 1, 1u128 << 96);
    }

    #[test]
    fn hosting_words_count_and_isp_words_veto() {
        let strong = Regex::new(STRONG).unwrap();
        let negative = Regex::new(NEGATIVE).unwrap();
        let hosting = |t: &str| {
            let hit = strong.find_iter(t).any(|m| !WEAK.contains(&m.as_str().to_lowercase().as_str()));
            hit && !negative.is_match(t)
        };
        assert!(hosting("HETZNER-fsn1-dc2 Hetzner Online GmbH Datacenter fsn1-dc2"));
        assert!(hosting("Timme Hosting GmbH & Co. KG"));
        assert!(!hosting("Shanghai DIA Dedicated Internet Access"));
        assert!(!hosting("Acme broadband customers hosting pool"));
        assert!(!hosting("Karsten Latvija VPN"));
        assert!(!hosting("Cloud Telecom Servers"));
    }
}
