pub use jiff::Timestamp;

pub fn now() -> Timestamp {
    from_unix(Timestamp::now().as_second())
}

pub fn from_unix(secs: i64) -> Timestamp {
    Timestamp::from_second(secs).unwrap_or(Timestamp::UNIX_EPOCH)
}

pub fn utc(ts: Timestamp) -> jiff::civil::DateTime {
    ts.to_zoned_datetime(jiff::tz::TimeZone::UTC).datetime()
}

pub fn date(ts: Timestamp) -> String {
    ts.strftime("%Y-%m-%d").to_string()
}

pub fn display(ts: Timestamp) -> String {
    ts.strftime("%Y-%m-%d %H:%M UTC").to_string()
}

#[derive(serde::Deserialize)]
#[serde(untagged)]
enum Wire {
    Iso(String),
    Unix(i64),
}

impl Wire {
    fn parse<E: serde::de::Error>(self) -> Result<Timestamp, E> {
        match self {
            Self::Iso(raw) => raw.parse().map_err(E::custom),
            Self::Unix(secs) => Timestamp::from_second(secs).map_err(E::custom),
        }
    }
}

pub mod rfc3339 {
    use serde::{Deserialize, Deserializer, Serializer};

    use super::{Timestamp, Wire};

    pub fn serialize<S: Serializer>(ts: &Timestamp, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_str(ts)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Timestamp, D::Error> {
        Wire::deserialize(deserializer)?.parse()
    }
}

pub mod rfc3339_opt {
    use serde::{Deserialize, Deserializer, Serializer};

    use super::{Timestamp, Wire};

    pub fn serialize<S: Serializer>(
        ts: &Option<Timestamp>,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        match ts {
            Some(ts) => serializer.collect_str(ts),
            None => serializer.serialize_none(),
        }
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<Option<Timestamp>, D::Error> {
        Option::<Wire>::deserialize(deserializer)?
            .map(Wire::parse)
            .transpose()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Debug, PartialEq, serde::Serialize, serde::Deserialize)]
    struct Record {
        #[serde(with = "rfc3339")]
        at: Timestamp,
        #[serde(default, with = "rfc3339_opt")]
        seen: Option<Timestamp>,
    }

    #[test]
    fn serializes_rfc3339_and_reads_legacy_unix_seconds() {
        let record = Record {
            at: from_unix(1_700_000_000),
            seen: None,
        };
        let json = serde_json::to_value(&record).unwrap();
        assert_eq!(
            json,
            serde_json::json!({ "at": "2023-11-14T22:13:20Z", "seen": null })
        );
        assert_eq!(serde_json::from_value::<Record>(json).unwrap(), record);

        let legacy: Record =
            serde_json::from_str(r#"{"at": 1700000000, "seen": 1700000060}"#).unwrap();
        assert_eq!(legacy.at, record.at);
        assert_eq!(legacy.seen, Some(from_unix(1_700_000_060)));
        let missing: Record = serde_json::from_str(r#"{"at": "2023-11-14T22:13:20Z"}"#).unwrap();
        assert_eq!(missing.seen, None);
        assert!(serde_json::from_str::<Record>(r#"{"at": "yesterday"}"#).is_err());
    }

    #[test]
    fn formats_for_people() {
        assert_eq!(display(from_unix(0)), "1970-01-01 00:00 UTC");
        assert_eq!(display(from_unix(1_700_000_000)), "2023-11-14 22:13 UTC");
        assert_eq!(display(from_unix(86_399)), "1970-01-01 23:59 UTC");
        assert_eq!(date(from_unix(951_782_400)), "2000-02-29");
        assert_eq!(date(from_unix(1_709_164_800)), "2024-02-29");
        assert_eq!(utc(from_unix(0)).weekday().to_monday_one_offset(), 4);
        assert_eq!(now().subsec_nanosecond(), 0, "second precision");
    }
}
