/// Parsed representation of Trillian's TLS-serialized LogRootV1.
///
/// Binary layout (all integers big-endian):
/// ```text
/// [2B version=1][8B tree_size][1B hash_len][hash_len B root_hash]
/// [8B timestamp_nanos][8B revision][2B metadata_len][metadata_len B metadata]
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LogRootV1 {
    pub tree_size: u64,
    pub root_hash: Vec<u8>,
    pub timestamp_nanos: u64,
    pub revision: u64,
    pub metadata: Vec<u8>,
}

#[derive(Debug, thiserror::Error)]
pub enum ParseLogRootError {
    #[error("log root too short: need at least {expected} bytes, got {actual}")]
    TooShort { expected: usize, actual: usize },
    #[error("unsupported log root version: {0} (expected 1)")]
    UnsupportedVersion(u16),
    #[error("unexpected trailing data: {0} bytes")]
    TrailingData(usize),
}

impl LogRootV1 {
    /// Parse a TLS-serialized LogRootV1 from the `SignedLogRoot.log_root` bytes.
    pub fn parse(data: &[u8]) -> Result<Self, ParseLogRootError> {
        // Minimum: 2 (version) + 8 (tree_size) + 1 (hash_len) + 0 (hash) +
        //          8 (timestamp) + 8 (revision) + 2 (metadata_len) = 29
        if data.len() < 29 {
            return Err(ParseLogRootError::TooShort {
                expected: 29,
                actual: data.len(),
            });
        }

        let mut pos = 0;

        // Version (2 bytes, big-endian)
        let version = u16::from_be_bytes([data[pos], data[pos + 1]]);
        pos += 2;
        if version != 1 {
            return Err(ParseLogRootError::UnsupportedVersion(version));
        }

        // Tree size (8 bytes, big-endian)
        let tree_size = u64::from_be_bytes(data[pos..pos + 8].try_into().unwrap());
        pos += 8;

        // Root hash length (1 byte)
        let hash_len = data[pos] as usize;
        pos += 1;

        if data.len() < pos + hash_len + 18 {
            return Err(ParseLogRootError::TooShort {
                expected: pos + hash_len + 18,
                actual: data.len(),
            });
        }

        // Root hash
        let root_hash = data[pos..pos + hash_len].to_vec();
        pos += hash_len;

        // Timestamp nanos (8 bytes, big-endian)
        let timestamp_nanos = u64::from_be_bytes(data[pos..pos + 8].try_into().unwrap());
        pos += 8;

        // Revision (8 bytes, big-endian)
        let revision = u64::from_be_bytes(data[pos..pos + 8].try_into().unwrap());
        pos += 8;

        // Metadata length (2 bytes, big-endian)
        let metadata_len = u16::from_be_bytes([data[pos], data[pos + 1]]) as usize;
        pos += 2;

        if data.len() < pos + metadata_len {
            return Err(ParseLogRootError::TooShort {
                expected: pos + metadata_len,
                actual: data.len(),
            });
        }

        let metadata = data[pos..pos + metadata_len].to_vec();
        pos += metadata_len;

        if pos != data.len() {
            return Err(ParseLogRootError::TrailingData(data.len() - pos));
        }

        Ok(LogRootV1 {
            tree_size,
            root_hash,
            timestamp_nanos,
            revision,
            metadata,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn build_log_root_v1(
        tree_size: u64,
        root_hash: &[u8],
        timestamp_nanos: u64,
        revision: u64,
        metadata: &[u8],
    ) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.extend_from_slice(&1u16.to_be_bytes()); // version
        buf.extend_from_slice(&tree_size.to_be_bytes());
        buf.push(root_hash.len() as u8);
        buf.extend_from_slice(root_hash);
        buf.extend_from_slice(&timestamp_nanos.to_be_bytes());
        buf.extend_from_slice(&revision.to_be_bytes());
        buf.extend_from_slice(&(metadata.len() as u16).to_be_bytes());
        buf.extend_from_slice(metadata);
        buf
    }

    #[test]
    fn parse_empty_tree() {
        let root_hash = [0u8; 32];
        let data = build_log_root_v1(0, &root_hash, 1000, 0, &[]);
        let parsed = LogRootV1::parse(&data).unwrap();
        assert_eq!(parsed.tree_size, 0);
        assert_eq!(parsed.root_hash, root_hash);
        assert_eq!(parsed.timestamp_nanos, 1000);
        assert_eq!(parsed.revision, 0);
        assert!(parsed.metadata.is_empty());
    }

    #[test]
    fn parse_with_metadata() {
        let root_hash = [0xAB; 32];
        let metadata = b"test-metadata";
        let data = build_log_root_v1(42, &root_hash, 999999, 7, metadata);
        let parsed = LogRootV1::parse(&data).unwrap();
        assert_eq!(parsed.tree_size, 42);
        assert_eq!(parsed.root_hash, root_hash.to_vec());
        assert_eq!(parsed.revision, 7);
        assert_eq!(parsed.metadata, metadata.to_vec());
    }

    #[test]
    fn reject_bad_version() {
        let mut data = build_log_root_v1(0, &[0; 32], 0, 0, &[]);
        data[0] = 0;
        data[1] = 2; // version 2
        assert!(matches!(
            LogRootV1::parse(&data),
            Err(ParseLogRootError::UnsupportedVersion(2))
        ));
    }

    #[test]
    fn reject_too_short() {
        assert!(matches!(
            LogRootV1::parse(&[0; 10]),
            Err(ParseLogRootError::TooShort { .. })
        ));
    }

    #[test]
    fn reject_trailing_data() {
        let mut data = build_log_root_v1(0, &[0; 32], 0, 0, &[]);
        data.push(0xFF);
        assert!(matches!(
            LogRootV1::parse(&data),
            Err(ParseLogRootError::TrailingData(1))
        ));
    }
}
