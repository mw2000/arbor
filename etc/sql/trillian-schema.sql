-- Trillian MySQL schema (from google/trillian storage/mysql/schema/storage.sql)

CREATE TABLE IF NOT EXISTS Trees(
  TreeId                BIGINT NOT NULL,
  TreeState             ENUM('ACTIVE', 'FROZEN', 'DRAINING') NOT NULL,
  TreeType              ENUM('LOG', 'MAP', 'PREORDERED_LOG') NOT NULL,
  HashStrategy          ENUM('RFC6962_SHA256', 'TEST_MAP_HASHER', 'OBJECT_RFC6962_SHA256', 'CONIKS_SHA512_256', 'CONIKS_SHA256') NOT NULL,
  HashAlgorithm         ENUM('SHA256') NOT NULL,
  SignatureAlgorithm    ENUM('ECDSA', 'RSA', 'ED25519') NOT NULL,
  DisplayName           VARCHAR(20),
  Description           VARCHAR(200),
  CreateTimeMillis      BIGINT NOT NULL,
  UpdateTimeMillis      BIGINT NOT NULL,
  MaxRootDurationMillis BIGINT NOT NULL,
  PrivateKey            MEDIUMBLOB NOT NULL,
  PublicKey             MEDIUMBLOB NOT NULL,
  Deleted               BOOLEAN,
  DeleteTimeMillis      BIGINT,
  PRIMARY KEY(TreeId)
);

CREATE TABLE IF NOT EXISTS TreeControl(
  TreeId                  BIGINT NOT NULL,
  SigningEnabled          BOOLEAN NOT NULL,
  SequencingEnabled       BOOLEAN NOT NULL,
  SequenceIntervalSeconds INTEGER NOT NULL,
  PRIMARY KEY(TreeId),
  FOREIGN KEY(TreeId) REFERENCES Trees(TreeId) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS Subtree(
  TreeId               BIGINT NOT NULL,
  SubtreeId            VARBINARY(255) NOT NULL,
  Nodes                MEDIUMBLOB NOT NULL,
  SubtreeRevision      INTEGER NOT NULL,
  PRIMARY KEY(TreeId, SubtreeId, SubtreeRevision),
  FOREIGN KEY(TreeId) REFERENCES Trees(TreeId) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS TreeHead(
  TreeId               BIGINT NOT NULL,
  TreeHeadTimestamp    BIGINT,
  TreeSize             BIGINT,
  RootHash             VARBINARY(255) NOT NULL,
  RootSignature        VARBINARY(1024) NOT NULL,
  TreeRevision         BIGINT,
  PRIMARY KEY(TreeId, TreeHeadTimestamp),
  FOREIGN KEY(TreeId) REFERENCES Trees(TreeId) ON DELETE CASCADE
);

CREATE UNIQUE INDEX TreeHeadRevisionIdx
  ON TreeHead(TreeId, TreeRevision);

CREATE TABLE IF NOT EXISTS LeafData(
  TreeId               BIGINT NOT NULL,
  LeafIdentityHash     VARBINARY(255) NOT NULL,
  LeafValue            LONGBLOB NOT NULL,
  ExtraData            LONGBLOB,
  QueueTimestampNanos  BIGINT NOT NULL,
  PRIMARY KEY(TreeId, LeafIdentityHash),
  FOREIGN KEY(TreeId) REFERENCES Trees(TreeId) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS SequencedLeafData(
  TreeId               BIGINT NOT NULL,
  SequenceNumber       BIGINT UNSIGNED NOT NULL,
  LeafIdentityHash     VARBINARY(255) NOT NULL,
  MerkleLeafHash       VARBINARY(255) NOT NULL,
  IntegrateTimestampNanos BIGINT NOT NULL,
  PRIMARY KEY(TreeId, SequenceNumber),
  FOREIGN KEY(TreeId) REFERENCES Trees(TreeId) ON DELETE CASCADE,
  FOREIGN KEY(TreeId, LeafIdentityHash) REFERENCES LeafData(TreeId, LeafIdentityHash) ON DELETE CASCADE
);

CREATE INDEX SequencedLeafMerkleIdx
  ON SequencedLeafData(TreeId, MerkleLeafHash);

CREATE TABLE IF NOT EXISTS Unsequenced(
  TreeId               BIGINT NOT NULL,
  Bucket               INTEGER NOT NULL,
  LeafIdentityHash     VARBINARY(255) NOT NULL,
  MerkleLeafHash       VARBINARY(255) NOT NULL,
  QueueTimestampNanos  BIGINT NOT NULL,
  QueueID VARBINARY(32) DEFAULT NULL UNIQUE,
  PRIMARY KEY (TreeId, Bucket, QueueTimestampNanos, LeafIdentityHash)
);
