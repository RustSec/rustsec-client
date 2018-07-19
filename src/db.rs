//! Database containing `RustSec` security advisories

use ADVISORY_DB_URL;
use advisory::Advisory;
use error::{Error, Result};
use reqwest;
use semver::Version;
use std::collections::HashMap;
use std::collections::hash_map::Entry::{Occupied, Vacant};
use std::collections::hash_map::Iter;
use std::io::Read;
use std::str;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use chrono::DateTime;
use toml;

/// A collection of security advisories, indexed both by ID and crate
#[derive(Debug)]
pub struct AdvisoryDatabase {
    advisories: HashMap<String, Advisory>,
    crates: HashMap<String, Vec<String>>,
    last_maintained: Option<SystemTime>,
}

impl AdvisoryDatabase {
    /// Fetch the advisory database from the server where it is stored
    pub fn fetch() -> Result<Self> {
        Self::fetch_from_url(ADVISORY_DB_URL)
    }

    /// Fetch advisory database from a custom URL
    pub fn fetch_from_url(url: &str) -> Result<Self> {
        let mut response = reqwest::get(url).or(Err(Error::IO))?;

        if !response.status().is_success() {
            return Err(Error::ServerResponse);
        }

        let mut body = Vec::new();
        response.read_to_end(&mut body).or(Err(Error::ServerResponse))?;
        let response_str = str::from_utf8(&body).or(Err(Error::Parse))?;

        Self::from_toml(response_str)
    }

    /// Parse the advisory database from a TOML serialization of it
    pub fn from_toml(data: &str) -> Result<Self> {
        let db_toml = data.parse::<toml::Value>().or(Err(Error::Parse))?;

        let db_table = match db_toml {
            toml::Value::Table(ref table) => {
                table
            }
            _ => return Err(Error::InvalidAttribute),
        };

        let advisories_toml = match *db_table.get("advisory").ok_or(Error::MissingAttribute)? {
            toml::Value::Array(ref arr) => arr,
            _ => return Err(Error::InvalidAttribute),
        };

        let mut advisories = HashMap::new();
        let mut crates = HashMap::<String, Vec<String>>::new();

        for advisory_toml in advisories_toml.iter() {
            let advisory = match *advisory_toml {
                toml::Value::Table(ref table) => Advisory::from_toml_table(table)?,
                _ => return Err(Error::InvalidAttribute),
            };

            let mut crate_vec = match crates.entry(advisory.package.clone()) {
                Vacant(entry) => entry.insert(Vec::new()),
                Occupied(entry) => entry.into_mut(),
            };

            crate_vec.push(advisory.id.clone());
            advisories.insert(advisory.id.clone(), advisory);
        }

        let meta_toml = match db_table.get("meta") {
            Some(toml::Value::Table(ref tbl)) => Some(tbl),
            _ => None,
        };

        let last_maintained = meta_toml
            .and_then(|t| t.get("last_maintained"))
            .and_then(|v| toml::Value::as_datetime(v))
            .map(toml::value::Datetime::to_string)
            .and_then(|s| DateTime::parse_from_rfc3339(&s).ok())
            .and_then(|d| {
                let secs = d.timestamp();
                let subsec = d.timestamp_subsec_nanos();

                if secs < 0 {
                    None
                } else {
                    Some(Duration::new(secs as u64, subsec))
                }
            })
            .map(|d| UNIX_EPOCH + d);

        Ok(AdvisoryDatabase {
            last_maintained: last_maintained,
            advisories: advisories,
            crates: crates,
        })
    }

    /// Look up an advisory by an advisory ID (e.g. "RUSTSEC-YYYY-XXXX")
    pub fn find(&self, id: &str) -> Option<&Advisory> {
        self.advisories.get(id)
    }

    /// Look up advisories relevant to a particular crate
    pub fn find_by_crate(&self, crate_name: &str) -> Vec<&Advisory> {
        let ids = self.crates.get(crate_name);
        let mut result = Vec::new();

        if ids.is_some() {
            for id in ids.unwrap() {
                result.push(self.find(id).unwrap())
            }
        }

        result
    }

    /// Find advisories that are unpatched and impact a given crate and version
    pub fn find_vulns_for_crate(&self, crate_name: &str, version: &Version) -> Vec<&Advisory> {
        let mut results = self.find_by_crate(crate_name);

        results.retain(|advisory| {
            !advisory.patched_versions.iter().any(|req| req.matches(version))
        });

        results
    }

    /// Iterate over all of the advisories in the database
    pub fn iter(&self) -> Iter<String, Advisory> {
        self.advisories.iter()
    }

    /// The time this database was last checked for new advisories
    pub fn last_maintained(&self) -> Option<SystemTime> {
        self.last_maintained
    }
}

#[cfg(test)]
mod tests {
    use db::AdvisoryDatabase;
    use semver::Version;
    use std::time::{Duration, UNIX_EPOCH};

    pub const EXAMPLE_PACKAGE: &'static str = "heffalump";
    pub const EXAMPLE_VERSION: &'static str = "1.0.0";
    pub const EXAMPLE_ADVISORY: &'static str = "RUSTSEC-1234-0001";

    pub const EXAMPLE_ADVISORIES: &'static str = r#"
        [meta]
        last_maintained = 2018-07-19T18:23:16+00:00

        [[advisory]]
        id = "RUSTSEC-1234-0001"
        package = "heffalump"
        patched_versions = [">= 1.1.0"]
        date = "2017-01-01"
        title = "Remote code execution vulnerability in heffalump service"
        description = """
        The heffalump service contained a shell escaping vulnerability which could
        be exploited by an attacker to perform arbitrary code execution.

        The issue was corrected by use of proper shell escaping.
        """
    "#;

    fn example_advisory_db() -> AdvisoryDatabase {
        AdvisoryDatabase::from_toml(EXAMPLE_ADVISORIES).unwrap()
    }

    #[test]
    fn test_find_vulns_for_crate() {
        let db = example_advisory_db();
        let version = Version::parse(EXAMPLE_VERSION).unwrap();
        let advisories = db.find_vulns_for_crate(EXAMPLE_PACKAGE, &version);

        assert_eq!(advisories[0], db.find(EXAMPLE_ADVISORY).unwrap());
    }

    #[test]
    fn test_last_maintained() {
        let db = example_advisory_db();
        let expected = Some(UNIX_EPOCH + Duration::from_secs(1532024596));

        assert_eq!(db.last_maintained(), expected);
    }
}
