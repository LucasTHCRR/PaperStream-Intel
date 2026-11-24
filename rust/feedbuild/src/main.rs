// SPDX-License-Identifier: AGPL-3.0-or-later
// Baut das Netzfeed wie feedbuild.py: iptoasn (ASN pro Bereich) plus APNIC aspop (Nutzer pro ASN).
use flate2::read::GzDecoder;
use flate2::write::GzEncoder;
use flate2::Compression;
use regex::Regex;
use serde_json::Value;
use std::collections::{HashMap, HashSet};
use std::fs;
use std::io::{BufRead, BufReader, Write};
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

const MIN_USERS: f64 = 50_000.0;
const UA: &str = "PaperStream-Feed/0 (support@paperstream.dev)";
const CLOUD: &str = r"(?i)\b(amazon|aws|google|microsoft|azure|ovh|hetzner|digitalocean|linode|akamai|vultr|choopa|contabo|leaseweb|m247|scaleway|oracle|alibaba|tencent|cloudflare|ionos|packet|datacamp|zenlayer|psychz|quadranet|colocrossing|frantech|buyvm|serverius|stark industries|hostinger|namecheap)\b";
const HOSTING: &str = r"(?i)\b(hosting|hoster|host|cloud|server|servers|vps|datacenter|data center|colo|colocation|dedicated|cdn|vpn|proxy)\b";
const ISPISH: &str = r"(?i)\b(isp|internet service|telecom|telekom|broadband|cable|mobile|wireless|communications?|telephone|fibre|fiber|dsl)\b";
const WORKERS: usize = 4;

struct Row {
    start: u128,
    end: u128,
    kind: char,
    cc: String,
    asn: u64,
    version: u8,
}

fn fetch(root: &Path, url: &str, name: &str, max_age: u64) -> Result<Vec<u8>, String> {
    let path = root.join("cache").join(name);
    if let Ok(meta) = fs::metadata(&path) {
        let age = meta.modified().ok().and_then(|m| SystemTime::now().duration_since(m).ok()).unwrap_or(Duration::MAX);
        if age < Duration::from_secs(max_age) {
            return fs::read(&path).map_err(|e| e.to_string());
        }
    }
    let temporary = path.with_extension("part");
    let status = Command::new("curl")
        .args(["-sSfL", "--max-time", "120", "-A", UA, "-o"])
        .arg(&temporary)
        .arg(url)
        .status()
        .map_err(|e| e.to_string())?;
    if !status.success() {
        return Err(format!("curl failed for {url}"));
    }
    fs::rename(&temporary, &path).map_err(|e| e.to_string())?;
    fs::read(&path).map_err(|e| e.to_string())
}

fn to_number(value: &Value) -> Option<u64> {
    match value {
        Value::Number(n) => n.as_u64().or_else(|| n.as_f64().map(|f| f as u64)),
        Value::String(s) => s.trim().parse().ok(),
        _ => None,
    }
}

// Pro Land: (ASNs mit mindestens MIN_USERS, ASNs mit irgendwelchen Nutzern)
fn aspop(root: &Path, cc: &str) -> Result<(Vec<u64>, Vec<u64>), String> {
    let raw = fetch(root, &format!("https://stats.labs.apnic.net/cgi-bin/aspop?c={cc}&f=j"), &format!("aspop-{cc}.json"), 7 * 86400)?;
    let json: Value = serde_json::from_slice(&raw).map_err(|e| e.to_string())?;
    let rows = json.get("Data").and_then(|d| d.as_array()).ok_or("no Data")?;
    let (mut big, mut any) = (Vec::new(), Vec::new());
    for row in rows {
        let users = match row.get("Users") {
            None => 0.0,
            Some(Value::Number(n)) => n.as_f64().unwrap_or(0.0),
            Some(_) => return Err("bad Users".into()),
        };
        let asn = to_number(row.get("AS").ok_or("no AS")?).ok_or("bad AS")?;
        if users > 0.0 {
            any.push(asn);
        }
        if users >= MIN_USERS {
            big.push(asn);
        }
    }
    Ok((big, any))
}

fn parse_ip(text: &str) -> Option<(u128, u8)> {
    match text.parse::<IpAddr>().ok()? {
        IpAddr::V4(a) => Some((u32::from(a) as u128, 4)),
        IpAddr::V6(a) => Some((u128::from(a), 6)),
    }
}

// Datum (UTC) ohne Zusatzpaket, Algorithmus nach Howard Hinnant
fn today() -> String {
    let days = (SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() / 86400) as i64;
    let z = days + 719468;
    let era = z.div_euclid(146097);
    let doe = z.rem_euclid(146097);
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    format!("{:04}-{:02}-{:02}", if m <= 2 { y + 1 } else { y }, m, d)
}

fn main() -> Result<(), String> {
    let root = PathBuf::from(std::env::var("FEED_WORK").unwrap_or_else(|_| ".".into()));
    fs::create_dir_all(root.join("cache")).map_err(|e| e.to_string())?;
    let raw = fetch(&root, "https://iptoasn.com/data/ip2asn-combined.tsv.gz", "ip2asn.tsv.gz", 86400)?;

    let mut rows: Vec<(u128, u128, u64, String, String, u8)> = Vec::new();
    let mut countries: HashSet<String> = HashSet::new();
    let mut skipped = 0usize;
    for line in BufReader::new(GzDecoder::new(&raw[..])).split(b'\n') {
        let line = String::from_utf8_lossy(&line.map_err(|e| e.to_string())?).into_owned();
        let fields: Vec<&str> = line.trim_end_matches('\r').split('\t').collect();
        if fields.len() < 5 {
            continue;
        }
        if fields[2] == "0" {
            continue;
        }
        let cc = if fields[3] == "None" || fields[3].is_empty() { "ZZ" } else { fields[3] };
        let (Some((start, version)), Some((end, _)), Ok(asn)) = (parse_ip(fields[0]), parse_ip(fields[1]), fields[2].parse::<u64>()) else {
            skipped += 1;
            continue;
        };
        rows.push((start, end, asn, cc.to_string(), fields[4].to_string(), version));
        countries.insert(cc.to_string());
    }
    countries.remove("ZZ");
    let mut codes: Vec<String> = countries.into_iter().collect();
    codes.sort();

    // APNIC pro Land abfragen, ein paar Faeden gleichzeitig
    let queue = Arc::new(Mutex::new(codes.clone().into_iter().enumerate().collect::<Vec<_>>()));
    let results = Arc::new(Mutex::new(HashMap::new()));
    let total = codes.len();
    let mut handles = Vec::new();
    for _ in 0..WORKERS {
        let (queue, results, root) = (queue.clone(), results.clone(), root.clone());
        handles.push(thread::spawn(move || loop {
            let Some((index, cc)) = queue.lock().unwrap().pop() else { break };
            let outcome = aspop(&root, &cc);
            if let Err(error) = &outcome {
                eprintln!("aspop {cc} failed: {}", error.chars().take(80).collect::<String>());
            }
            if index % 20 == 0 {
                eprintln!("aspop {index} / {total}");
            }
            results.lock().unwrap().insert(cc, outcome);
        }));
    }
    for handle in handles {
        handle.join().map_err(|_| "worker panicked")?;
    }
    let results = results.lock().unwrap();
    let mut users: HashSet<(u64, String)> = HashSet::new();
    let mut seen: HashSet<(u64, String)> = HashSet::new();
    let mut answered: HashSet<String> = HashSet::new();
    for (cc, outcome) in results.iter() {
        if let Ok((big, any)) = outcome {
            users.extend(big.iter().map(|a| (*a, cc.clone())));
            seen.extend(any.iter().map(|a| (*a, cc.clone())));
            answered.insert(cc.clone());
        }
    }

    let (cloud, hosting, ispish) = (Regex::new(CLOUD).unwrap(), Regex::new(HOSTING).unwrap(), Regex::new(ISPISH).unwrap());
    let mut out: Vec<(u128, u128, char, String, u64, u8)> = Vec::with_capacity(rows.len());
    for (start, end, asn, cc, description, version) in rows {
        let key = (asn, cc.clone());
        let kind = if cloud.is_match(&description) {
            'H'
        } else if hosting.is_match(&description) && !ispish.is_match(&description) {
            'H'
        } else if users.contains(&key) {
            'E'
        } else if answered.contains(&cc) && !seen.contains(&key) && !ispish.is_match(&description) {
            'N'
        } else {
            'S'
        };
        out.push((start, end, kind, cc, asn, version));
    }
    out.sort();
    let mut merged: Vec<Row> = Vec::with_capacity(out.len());
    for (start, end, kind, cc, asn, version) in out {
        match merged.last_mut() {
            Some(last) if last.kind == kind && last.cc == cc && last.asn == asn && last.version == version && start <= last.end + 1 => {
                last.end = last.end.max(end);
            }
            _ => merged.push(Row { start, end, kind, cc, asn, version }),
        }
    }

    let target = root.join("out").join("asn-feed.tsv.gz");
    fs::create_dir_all(target.parent().unwrap()).map_err(|e| e.to_string())?;
    let mut writer = GzEncoder::new(fs::File::create(&target).map_err(|e| e.to_string())?, Compression::best());
    let mut text = String::with_capacity(merged.len() * 40);
    text.push_str("# PaperStream network feed. iptoasn.com (public domain), APNIC aspop (attribution: APNIC).\n");
    text.push_str(&format!("# built {}; E end-user network (>= {} users), H hosting-like\n", today(), MIN_USERS as u64));
    for r in &merged {
        text.push_str(&format!("{}\t{}\t{}\t{}\t{}\t{}\n", r.start, r.end, r.kind, r.cc, r.asn, r.version));
    }
    writer.write_all(text.as_bytes()).map_err(|e| e.to_string())?;
    writer.finish().map_err(|e| e.to_string())?;
    if skipped > 0 {
        eprintln!("skipped {skipped} unreadable lines");
    }
    println!("rows {} size {}", merged.len(), fs::metadata(&target).map_err(|e| e.to_string())?.len());
    Ok(())
}
