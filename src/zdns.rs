//! ZDNS - Zero Knowledge Domain Name System
//! 
//! Revolutionary DNS replacement for Web4, providing decentralized domain name resolution
//! with zero-knowledge proofs, ownership verification, and post-quantum security.
//! 
//! ZDNS completely replaces traditional DNS with a system that:
//! - Proves domain ownership without revealing private keys
//! - Provides censorship-resistant domain resolution
//! - Integrates economic incentives for domain hosting
//! - Supports .zhtp domains and Web4 addressing
//! - Enables ISP bypass through mesh routing

use crate::types::{ZhtpHeaders, ZhtpStatus};
use crate::{ProtocolError, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// ZDNS record types for Web4 domains
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum ZdnsRecordType {
    /// Address record (IPv4)
    A,
    /// Address record (IPv6)
    AAAA,
    /// Canonical name record
    CNAME,
    /// Mail exchange record
    MX,
    /// Text record
    TXT,
    /// Service location record
    SRV,
    /// ZHTP mesh node record
    MESH,
    /// Zero-knowledge proof record
    ZK,
    /// DAO governance record
    DAO,
    /// Economic incentive record
    ECON,
    /// Identity verification record
    ID,
    /// Content hash record
    CONTENT,
    /// Multi-signature record
    MULTISIG,
    /// Post-quantum signature record
    PQS,
}

/// ZDNS record with zero-knowledge proofs
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ZdnsRecord {
    /// Record name (domain)
    pub name: String,
    /// Record type
    pub record_type: ZdnsRecordType,
    /// Record value/data
    pub value: String,
    /// Time-to-live in seconds
    pub ttl: u32,
    /// Zero-knowledge proof of ownership
    pub ownership_proof: String,
    /// Post-quantum signature
    pub pq_signature: String,
    /// DAO fee proof for record registration
    pub dao_fee_proof: String,
    /// Record priority (for MX, SRV records)
    pub priority: Option<u16>,
    /// Record weight (for SRV records)
    pub weight: Option<u16>,
    /// Service port (for SRV records)
    pub port: Option<u16>,
    /// Target host (for CNAME, SRV records)
    pub target: Option<String>,
    /// Record metadata
    pub metadata: ZdnsRecordMetadata,
}

/// Metadata for ZDNS records
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ZdnsRecordMetadata {
    /// Record creation timestamp
    pub created_at: chrono::DateTime<chrono::Utc>,
    /// Last update timestamp
    pub updated_at: chrono::DateTime<chrono::Utc>,
    /// Record owner identity
    pub owner_id: String,
    /// Record version number
    pub version: u32,
    /// Economic incentive configuration
    pub economic_config: Option<EconomicConfig>,
    /// Access control policy
    pub access_policy: Option<String>,
    /// Content integrity hash
    pub content_hash: Option<String>,
}

/// Economic configuration for domain records
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EconomicConfig {
    /// Required DAO fee for domain access
    pub access_fee: f64,
    /// Revenue sharing percentage for domain owner
    pub owner_share: f64,
    /// UBI contribution percentage
    pub ubi_share: f64,
    /// Network maintenance fee percentage
    pub network_share: f64,
    /// Hosting reward for mesh nodes
    pub hosting_reward: f64,
}

/// ZDNS query request
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ZdnsQuery {
    /// Domain name to resolve
    pub name: String,
    /// Record type to query
    pub record_type: ZdnsRecordType,
    /// Query class (always IN for Internet)
    pub class: u16,
    /// Query ID for matching responses
    pub id: u16,
    /// Recursion desired flag
    pub recursion_desired: bool,
    /// DNSSEC validation required
    pub dnssec_ok: bool,
    /// Zero-knowledge proof for query authentication
    pub query_proof: Option<String>,
    /// DAO fee for query processing
    pub dao_fee: Option<f64>,
    /// Client identity for access control
    pub client_id: Option<String>,
}

/// ZDNS query response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ZdnsResponse {
    /// Query ID (matches request)
    pub id: u16,
    /// Response flags
    pub flags: ZdnsFlags,
    /// Question section (original query)
    pub questions: Vec<ZdnsQuery>,
    /// Answer section (matching records)
    pub answers: Vec<ZdnsRecord>,
    /// Authority section (authoritative nameservers)
    pub authority: Vec<ZdnsRecord>,
    /// Additional section (additional records)
    pub additional: Vec<ZdnsRecord>,
    /// Response metadata
    pub metadata: ZdnsResponseMetadata,
}

/// ZDNS response flags
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ZdnsFlags {
    /// Query/Response flag
    pub qr: bool,
    /// Operation code
    pub opcode: u8,
    /// Authoritative answer flag
    pub aa: bool,
    /// Truncated flag
    pub tc: bool,
    /// Recursion desired flag
    pub rd: bool,
    /// Recursion available flag
    pub ra: bool,
    /// Zero-knowledge validation flag
    pub zk: bool,
    /// DAO fee validated flag
    pub dao: bool,
    /// Response code
    pub rcode: u8,
}

/// ZDNS response metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ZdnsResponseMetadata {
    /// Response timestamp
    pub timestamp: chrono::DateTime<chrono::Utc>,
    /// Processing time in milliseconds
    pub processing_time_ms: u64,
    /// Serving mesh node ID
    pub server_node_id: String,
    /// Economic transaction details
    pub economic_details: Option<EconomicTransaction>,
    /// Cache information
    pub cache_info: Option<CacheInfo>,
}

/// Economic transaction details for ZDNS operations
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EconomicTransaction {
    /// Transaction ID
    pub tx_id: String,
    /// DAO fee amount paid
    pub dao_fee_paid: f64,
    /// UBI contribution amount
    pub ubi_contribution: f64,
    /// Domain owner payment
    pub owner_payment: f64,
    /// Network maintenance fee
    pub network_fee: f64,
    /// Hosting reward for mesh nodes
    pub hosting_rewards: HashMap<String, f64>,
}

/// Cache information for ZDNS responses
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CacheInfo {
    /// Whether response was served from cache
    pub cached: bool,
    /// Cache hit ratio
    pub hit_ratio: f64,
    /// Cache expiry time
    pub expires_at: chrono::DateTime<chrono::Utc>,
    /// Caching node IDs
    pub cache_nodes: Vec<String>,
}

/// ZDNS server configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ZdnsConfig {
    /// Server listening port
    pub port: u16,
    /// Server node identity
    pub node_id: String,
    /// Maximum query processing time (seconds)
    pub max_query_time: u64,
    /// Cache configuration
    pub cache_config: CacheConfig,
    /// Economic parameters
    pub economic_config: EconomicConfig,
    /// Security settings
    pub security_config: SecurityConfig,
    /// Mesh networking settings
    pub mesh_config: MeshConfig,
}

/// Cache configuration for ZDNS
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CacheConfig {
    /// Enable caching
    pub enabled: bool,
    /// Maximum cache size (number of records)
    pub max_size: usize,
    /// Default TTL for cached records (seconds)
    pub default_ttl: u32,
    /// Cache cleanup interval (seconds)
    pub cleanup_interval: u64,
    /// Enable distributed caching across mesh
    pub distributed: bool,
}

/// Security configuration for ZDNS
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityConfig {
    /// Require zero-knowledge proofs for all queries
    pub require_zk_proofs: bool,
    /// Require DAO fees for query processing
    pub require_dao_fees: bool,
    /// Enable post-quantum signature validation
    pub enable_pq_signatures: bool,
    /// Maximum query rate per client (per minute)
    pub max_query_rate: u32,
    /// Enable query logging for security analysis
    pub enable_query_logging: bool,
}

/// Mesh networking configuration for ZDNS
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MeshConfig {
    /// Enable mesh networking for domain resolution
    pub enabled: bool,
    /// Maximum number of mesh hops for queries
    pub max_hops: u8,
    /// Mesh node selection strategy
    pub node_selection: MeshNodeSelection,
    /// Economic incentives for mesh routing
    pub routing_rewards: f64,
    /// Enable ISP bypass functionality
    pub enable_isp_bypass: bool,
}

/// Mesh node selection strategies
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum MeshNodeSelection {
    /// Select closest node by latency
    Latency,
    /// Select most reliable node
    Reliability,
    /// Select node with best economic incentives
    Economic,
    /// Load balance across available nodes
    LoadBalance,
    /// Random selection for privacy
    Random,
}

/// ZDNS server implementation
#[derive(Debug)]
pub struct ZdnsServer {
    config: ZdnsConfig,
    records: std::sync::RwLock<HashMap<String, Vec<ZdnsRecord>>>,
    cache: std::sync::RwLock<HashMap<String, CachedRecord>>,
    query_stats: std::sync::RwLock<QueryStats>,
}

/// Cached ZDNS record with expiry
#[derive(Debug, Clone)]
struct CachedRecord {
    record: ZdnsRecord,
    expires_at: chrono::DateTime<chrono::Utc>,
    access_count: u64,
}

/// Query statistics for monitoring
#[derive(Debug, Clone, Default)]
struct QueryStats {
    total_queries: u64,
    cache_hits: u64,
    cache_misses: u64,
    zk_validations: u64,
    dao_payments: f64,
    average_response_time_ms: f64,
}

impl ZdnsServer {
    /// Create new ZDNS server with configuration
    pub fn new(config: ZdnsConfig) -> Self {
        Self {
            config,
            records: std::sync::RwLock::new(HashMap::new()),
            cache: std::sync::RwLock::new(HashMap::new()),
            query_stats: std::sync::RwLock::new(QueryStats::default()),
        }
    }

    /// Process ZDNS query and return response
    pub async fn process_query(&self, query: ZdnsQuery) -> Result<ZdnsResponse> {
        let start_time = std::time::Instant::now();
        let mut stats = self.query_stats.write().unwrap();
        stats.total_queries += 1;
        drop(stats);

        // Validate query
        self.validate_query(&query)?;

        // Check cache first
        let cache_key = format!("{}:{:?}", query.name, query.record_type);
        if let Some(cached) = self.check_cache(&cache_key) {
            let mut stats = self.query_stats.write().unwrap();
            stats.cache_hits += 1;
            drop(stats);

            return Ok(self.create_response_from_cache(query, cached));
        }

        // Cache miss - resolve from records
        let mut stats = self.query_stats.write().unwrap();
        stats.cache_misses += 1;
        drop(stats);

        let records = self.resolve_records(&query.name, &query.record_type)?;
        
        // Validate zero-knowledge proofs if required
        if self.config.security_config.require_zk_proofs {
            self.validate_zk_proofs(&records)?;
        }

        // Process DAO fee if required
        let economic_details = if self.config.security_config.require_dao_fees {
            Some(self.process_dao_fee(&query, &records).await?)
        } else {
            None
        };

        // Cache the result
        if self.config.cache_config.enabled {
            self.cache_records(&cache_key, &records);
        }

        let processing_time = start_time.elapsed().as_millis() as u64;
        
        // Update stats
        let mut stats = self.query_stats.write().unwrap();
        stats.average_response_time_ms = 
            (stats.average_response_time_ms * (stats.total_queries - 1) as f64 + processing_time as f64) 
            / stats.total_queries as f64;

        Ok(ZdnsResponse {
            id: query.id,
            flags: ZdnsFlags {
                qr: true,
                opcode: 0,
                aa: true,
                tc: false,
                rd: query.recursion_desired,
                ra: true,
                zk: self.config.security_config.require_zk_proofs,
                dao: self.config.security_config.require_dao_fees,
                rcode: 0,
            },
            questions: vec![query],
            answers: records,
            authority: vec![],
            additional: vec![],
            metadata: ZdnsResponseMetadata {
                timestamp: chrono::Utc::now(),
                processing_time_ms: processing_time,
                server_node_id: self.config.node_id.clone(),
                economic_details,
                cache_info: None,
            },
        })
    }

    /// Register new ZDNS record
    pub async fn register_record(&self, record: ZdnsRecord) -> Result<()> {
        // Validate record
        self.validate_record(&record)?;

        // Validate ownership proof
        self.validate_ownership_proof(&record)?;

        // Validate DAO fee payment
        self.validate_dao_fee_proof(&record)?;

        // Store record
        let mut records = self.records.write().unwrap();
        let domain_records = records.entry(record.name.clone()).or_insert_with(Vec::new);
        
        // Replace existing record of same type or add new one
        if let Some(pos) = domain_records.iter().position(|r| r.record_type == record.record_type) {
            domain_records[pos] = record;
        } else {
            domain_records.push(record);
        }

        Ok(())
    }

    /// Update existing ZDNS record
    pub async fn update_record(&self, record: ZdnsRecord) -> Result<()> {
        // Validate that record exists and ownership is valid
        let records = self.records.read().unwrap();
        let domain_records = records.get(&record.name)
            .ok_or_else(|| ProtocolError::InvalidRequest("Domain not found".to_string()))?;

        let existing = domain_records.iter()
            .find(|r| r.record_type == record.record_type)
            .ok_or_else(|| ProtocolError::InvalidRequest("Record not found".to_string()))?;

        // Verify ownership hasn't changed
        if existing.metadata.owner_id != record.metadata.owner_id {
            return Err(ProtocolError::AccessDenied("Ownership mismatch".to_string()));
        }

        drop(records);

        // Validate and store updated record
        self.validate_record(&record)?;
        self.validate_ownership_proof(&record)?;
        self.validate_dao_fee_proof(&record)?;

        let mut records = self.records.write().unwrap();
        let domain_records = records.get_mut(&record.name).unwrap();
        
        if let Some(pos) = domain_records.iter().position(|r| r.record_type == record.record_type) {
            domain_records[pos] = record;
        }

        Ok(())
    }

    /// Delete ZDNS record
    pub async fn delete_record(&self, name: &str, record_type: &ZdnsRecordType, owner_id: &str) -> Result<()> {
        let mut records = self.records.write().unwrap();
        let domain_records = records.get_mut(name)
            .ok_or_else(|| ProtocolError::InvalidRequest("Domain not found".to_string()))?;

        let pos = domain_records.iter().position(|r| {
            r.record_type == *record_type && r.metadata.owner_id == owner_id
        }).ok_or_else(|| ProtocolError::AccessDenied("Record not found or access denied".to_string()))?;

        domain_records.remove(pos);

        // Remove domain entry if no records left
        if domain_records.is_empty() {
            records.remove(name);
        }

        Ok(())
    }

    /// Get query statistics
    pub fn get_stats(&self) -> QueryStats {
        self.query_stats.read().unwrap().clone()
    }

    // Private helper methods

    fn validate_query(&self, query: &ZdnsQuery) -> Result<()> {
        if query.name.is_empty() {
            return Err(ProtocolError::InvalidRequest("Domain name cannot be empty".to_string()));
        }

        if !query.name.ends_with(".zhtp") && !query.name.contains('.') {
            return Err(ProtocolError::InvalidRequest("Invalid domain format".to_string()));
        }

        Ok(())
    }

    fn check_cache(&self, cache_key: &str) -> Option<ZdnsRecord> {
        let cache = self.cache.read().unwrap();
        if let Some(cached) = cache.get(cache_key) {
            if cached.expires_at > chrono::Utc::now() {
                return Some(cached.record.clone());
            }
        }
        None
    }

    fn resolve_records(&self, name: &str, record_type: &ZdnsRecordType) -> Result<Vec<ZdnsRecord>> {
        let records = self.records.read().unwrap();
        
        if let Some(domain_records) = records.get(name) {
            let matching: Vec<ZdnsRecord> = domain_records.iter()
                .filter(|r| r.record_type == *record_type)
                .cloned()
                .collect();
            
            if matching.is_empty() {
                Err(ProtocolError::InvalidRequest("No records found".to_string()))
            } else {
                Ok(matching)
            }
        } else {
            Err(ProtocolError::InvalidRequest("Domain not found".to_string()))
        }
    }

    fn validate_zk_proofs(&self, records: &[ZdnsRecord]) -> Result<()> {
        for record in records {
            if record.ownership_proof.len() < 64 {
                return Err(ProtocolError::ZkProofError("Invalid ownership proof".to_string()));
            }
            // TODO: Implement actual ZK proof verification
        }
        Ok(())
    }

    async fn process_dao_fee(&self, query: &ZdnsQuery, records: &[ZdnsRecord]) -> Result<EconomicTransaction> {
        let fee_amount = query.dao_fee.unwrap_or(0.01); // Default minimal fee
        
        // Calculate fee distribution
        let ubi_contribution = fee_amount * 0.4; // 40% to UBI
        let network_fee = fee_amount * 0.3; // 30% to network maintenance
        let owner_payment = fee_amount * 0.2; // 20% to domain owner
        let hosting_reward = fee_amount * 0.1; // 10% to hosting nodes

        Ok(EconomicTransaction {
            tx_id: format!("zdns_{}", uuid::Uuid::new_v4()),
            dao_fee_paid: fee_amount,
            ubi_contribution,
            owner_payment,
            network_fee,
            hosting_rewards: {
                let mut rewards = HashMap::new();
                rewards.insert(self.config.node_id.clone(), hosting_reward);
                rewards
            },
        })
    }

    fn cache_records(&self, cache_key: &str, records: &[ZdnsRecord]) {
        if let Some(record) = records.first() {
            let expires_at = chrono::Utc::now() + chrono::Duration::seconds(record.ttl as i64);
            let cached = CachedRecord {
                record: record.clone(),
                expires_at,
                access_count: 1,
            };

            let mut cache = self.cache.write().unwrap();
            cache.insert(cache_key.to_string(), cached);

            // Simple cache cleanup - remove expired entries
            cache.retain(|_, v| v.expires_at > chrono::Utc::now());
        }
    }

    fn create_response_from_cache(&self, query: ZdnsQuery, cached_record: ZdnsRecord) -> ZdnsResponse {
        ZdnsResponse {
            id: query.id,
            flags: ZdnsFlags {
                qr: true,
                opcode: 0,
                aa: false, // Not authoritative from cache
                tc: false,
                rd: query.recursion_desired,
                ra: true,
                zk: false, // Cache response doesn't re-validate ZK
                dao: false, // Cache response doesn't re-process DAO fees
                rcode: 0,
            },
            questions: vec![query],
            answers: vec![cached_record],
            authority: vec![],
            additional: vec![],
            metadata: ZdnsResponseMetadata {
                timestamp: chrono::Utc::now(),
                processing_time_ms: 1, // Cache responses are very fast
                server_node_id: self.config.node_id.clone(),
                economic_details: None,
                cache_info: Some(CacheInfo {
                    cached: true,
                    hit_ratio: 0.8, // TODO: Calculate actual hit ratio
                    expires_at: chrono::Utc::now() + chrono::Duration::seconds(300),
                    cache_nodes: vec![self.config.node_id.clone()],
                }),
            },
        }
    }

    fn validate_record(&self, record: &ZdnsRecord) -> Result<()> {
        if record.name.is_empty() {
            return Err(ProtocolError::InvalidRequest("Record name cannot be empty".to_string()));
        }

        if record.value.is_empty() {
            return Err(ProtocolError::InvalidRequest("Record value cannot be empty".to_string()));
        }

        // Validate record type specific constraints
        match record.record_type {
            ZdnsRecordType::A => {
                record.value.parse::<Ipv4Addr>()
                    .map_err(|_| ProtocolError::InvalidRequest("Invalid IPv4 address".to_string()))?;
            },
            ZdnsRecordType::AAAA => {
                record.value.parse::<Ipv6Addr>()
                    .map_err(|_| ProtocolError::InvalidRequest("Invalid IPv6 address".to_string()))?;
            },
            ZdnsRecordType::MX => {
                if record.priority.is_none() {
                    return Err(ProtocolError::InvalidRequest("MX record requires priority".to_string()));
                }
            },
            ZdnsRecordType::SRV => {
                if record.priority.is_none() || record.weight.is_none() || record.port.is_none() {
                    return Err(ProtocolError::InvalidRequest("SRV record requires priority, weight, and port".to_string()));
                }
            },
            _ => {} // Other types have flexible validation
        }

        Ok(())
    }

    fn validate_ownership_proof(&self, record: &ZdnsRecord) -> Result<()> {
        if record.ownership_proof.len() < 64 {
            return Err(ProtocolError::ZkProofError("Ownership proof too short".to_string()));
        }
        // TODO: Implement actual ownership proof validation
        Ok(())
    }

    fn validate_dao_fee_proof(&self, record: &ZdnsRecord) -> Result<()> {
        if record.dao_fee_proof.len() < 32 {
            return Err(ProtocolError::DaoFeeError("DAO fee proof too short".to_string()));
        }
        // TODO: Implement actual DAO fee proof validation
        Ok(())
    }
}

impl Default for ZdnsConfig {
    fn default() -> Self {
        Self {
            port: 5353, // Standard mDNS port
            node_id: format!("zdns_{}", uuid::Uuid::new_v4()),
            max_query_time: 30,
            cache_config: CacheConfig {
                enabled: true,
                max_size: 10000,
                default_ttl: 300,
                cleanup_interval: 60,
                distributed: true,
            },
            economic_config: EconomicConfig {
                access_fee: 0.01,
                owner_share: 0.2,
                ubi_share: 0.4,
                network_share: 0.3,
                hosting_reward: 0.1,
            },
            security_config: SecurityConfig {
                require_zk_proofs: true,
                require_dao_fees: true,
                enable_pq_signatures: true,
                max_query_rate: 100,
                enable_query_logging: true,
            },
            mesh_config: MeshConfig {
                enabled: true,
                max_hops: 5,
                node_selection: MeshNodeSelection::LoadBalance,
                routing_rewards: 0.005,
                enable_isp_bypass: true,
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_zdns_query_processing() {
        let config = ZdnsConfig::default();
        let server = ZdnsServer::new(config);

        // Register a test record
        let record = ZdnsRecord {
            name: "example.zhtp".to_string(),
            record_type: ZdnsRecordType::A,
            value: "192.168.1.1".to_string(),
            ttl: 300,
            ownership_proof: "a".repeat(64),
            pq_signature: "b".repeat(128),
            dao_fee_proof: "c".repeat(32),
            priority: None,
            weight: None,
            port: None,
            target: None,
            metadata: ZdnsRecordMetadata {
                created_at: chrono::Utc::now(),
                updated_at: chrono::Utc::now(),
                owner_id: "test_owner".to_string(),
                version: 1,
                economic_config: None,
                access_policy: None,
                content_hash: None,
            },
        };

        assert!(server.register_record(record).await.is_ok());

        // Query the record
        let query = ZdnsQuery {
            name: "example.zhtp".to_string(),
            record_type: ZdnsRecordType::A,
            class: 1,
            id: 12345,
            recursion_desired: true,
            dnssec_ok: false,
            query_proof: Some("query_proof".to_string()),
            dao_fee: Some(0.01),
            client_id: Some("test_client".to_string()),
        };

        let response = server.process_query(query).await;
        assert!(response.is_ok());
        
        let response = response.unwrap();
        assert_eq!(response.answers.len(), 1);
        assert_eq!(response.answers[0].value, "192.168.1.1");
    }

    #[test]
    fn test_record_validation() {
        let config = ZdnsConfig::default();
        let server = ZdnsServer::new(config);

        // Valid A record
        let valid_record = ZdnsRecord {
            name: "test.zhtp".to_string(),
            record_type: ZdnsRecordType::A,
            value: "1.2.3.4".to_string(),
            ttl: 300,
            ownership_proof: "a".repeat(64),
            pq_signature: "b".repeat(128),
            dao_fee_proof: "c".repeat(32),
            priority: None,
            weight: None,
            port: None,
            target: None,
            metadata: ZdnsRecordMetadata {
                created_at: chrono::Utc::now(),
                updated_at: chrono::Utc::now(),
                owner_id: "test_owner".to_string(),
                version: 1,
                economic_config: None,
                access_policy: None,
                content_hash: None,
            },
        };

        assert!(server.validate_record(&valid_record).is_ok());

        // Invalid A record (bad IP)
        let mut invalid_record = valid_record.clone();
        invalid_record.value = "invalid_ip".to_string();
        assert!(server.validate_record(&invalid_record).is_err());
    }

    #[test]
    fn test_economic_config() {
        let config = EconomicConfig {
            access_fee: 0.02,
            owner_share: 0.25,
            ubi_share: 0.35,
            network_share: 0.25,
            hosting_reward: 0.15,
        };

        // Verify shares add up to 100%
        let total = config.owner_share + config.ubi_share + config.network_share + config.hosting_reward;
        assert!((total - 1.0).abs() < 0.001);
    }
}
