use std::collections::HashMap;
use std::str::FromStr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use chrono::{DateTime, FixedOffset, NaiveDate, NaiveDateTime, NaiveTime};
use deadpool_postgres::{Manager, ManagerConfig, Pool, RecyclingMethod, Runtime};
use serde::Serialize;
use serde_json::Value;
use tokio::sync::Mutex;
use tokio::time::timeout;
use tokio_postgres::NoTls;
use tokio_postgres::config::Host;
use tokio_postgres::error::DbError;
use tokio_postgres::types::{Json, ToSql};
use uuid::Uuid;
use zeroize::Zeroize;

pub const DEFAULT_TIMEOUT_MS: u64 = 5_000;
pub const DEFAULT_MAX_ROWS: usize = 500;
const DEFAULT_POOL_SIZE: usize = 16;

#[derive(Debug, Serialize)]
pub struct DbQueryColumn {
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub db_type: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct DbQueryResult {
    pub columns: Vec<DbQueryColumn>,
    pub rows: Vec<Vec<Value>>,
    pub row_count: usize,
    pub truncated: bool,
    pub timing_ms: u128,
}

#[derive(Clone)]
pub struct DbPoolCache {
    entries: Arc<Mutex<HashMap<String, DbPoolEntry>>>,
    idle_ttl: Duration,
}

#[derive(Clone)]
struct DbPoolEntry {
    pool: Pool,
    last_used: Instant,
}

impl DbPoolCache {
    pub fn new(idle_ttl: Duration, sweep_interval: Duration) -> Self {
        let cache = Self {
            entries: Arc::new(Mutex::new(HashMap::new())),
            idle_ttl,
        };
        cache.spawn_evictor(sweep_interval);
        cache
    }

    fn spawn_evictor(&self, sweep_interval: Duration) {
        let entries = Arc::clone(&self.entries);
        let idle_ttl = self.idle_ttl;
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(sweep_interval).await;
                let now = Instant::now();
                let mut guard = entries.lock().await;
                guard.retain(|_, value| now.duration_since(value.last_used) <= idle_ttl);
            }
        });
    }

    pub async fn get_or_create_pool(
        &self,
        pool_key: &str,
        connection_string: &str,
    ) -> Result<Pool, anyhow::Error> {
        {
            let mut guard = self.entries.lock().await;
            if let Some(entry) = guard.get_mut(pool_key) {
                entry.last_used = Instant::now();
                return Ok(entry.pool.clone());
            }
        }

        let pool = create_pool(connection_string)?;

        let mut guard = self.entries.lock().await;
        let entry = guard.entry(pool_key.to_string()).or_insert(DbPoolEntry {
            pool: pool.clone(),
            last_used: Instant::now(),
        });
        entry.last_used = Instant::now();
        Ok(entry.pool.clone())
    }
}

fn create_pool(connection_string: &str) -> Result<Pool, anyhow::Error> {
    let config = tokio_postgres::Config::from_str(connection_string)?;
    let manager_config = ManagerConfig {
        recycling_method: RecyclingMethod::Fast,
    };
    let manager = Manager::from_config(config, NoTls, manager_config);
    let pool = Pool::builder(manager)
        .max_size(DEFAULT_POOL_SIZE)
        .runtime(Runtime::Tokio1)
        .build()?;
    Ok(pool)
}

pub fn connection_string_hash(connection_string: &str) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(connection_string.as_bytes());
    hex::encode(hasher.finalize())
}

pub fn parse_connection_targets(
    connection_string: &str,
) -> Result<Vec<(String, u16)>, anyhow::Error> {
    let config = tokio_postgres::Config::from_str(connection_string)?;
    let hosts = config.get_hosts();
    if hosts.is_empty() {
        return Err(anyhow::anyhow!(
            "connection string must include at least one TCP host"
        ));
    }
    let ports = config.get_ports();
    let mut output = Vec::new();
    for (index, host) in hosts.iter().enumerate() {
        let hostname = match host {
            Host::Tcp(value) => value.clone(),
            Host::Unix(_) => {
                return Err(anyhow::anyhow!(
                    "unix socket connections are not supported for db-query"
                ));
            }
        };
        let port = if ports.is_empty() {
            5432
        } else if let Some(value) = ports.get(index) {
            *value
        } else {
            *ports.last().unwrap_or(&5432)
        };
        output.push((hostname, port));
    }
    Ok(output)
}

#[derive(Debug)]
enum QueryParamOwned {
    Null(Option<String>),
    Bool(bool),
    Int16(i16),
    Int32(i32),
    Int(i64),
    Float(f64),
    Text(String),
    TimestampTz(DateTime<FixedOffset>),
    Timestamp(NaiveDateTime),
    Date(NaiveDate),
    Time(NaiveTime),
    Uuid(Uuid),
    Bytea(Vec<u8>),
    Json(Json<Value>),
}

impl QueryParamOwned {
    fn as_tosql(&self) -> &(dyn ToSql + Sync) {
        match self {
            QueryParamOwned::Null(value) => value,
            QueryParamOwned::Bool(value) => value,
            QueryParamOwned::Int16(value) => value,
            QueryParamOwned::Int32(value) => value,
            QueryParamOwned::Int(value) => value,
            QueryParamOwned::Float(value) => value,
            QueryParamOwned::Text(value) => value,
            QueryParamOwned::TimestampTz(value) => value,
            QueryParamOwned::Timestamp(value) => value,
            QueryParamOwned::Date(value) => value,
            QueryParamOwned::Time(value) => value,
            QueryParamOwned::Uuid(value) => value,
            QueryParamOwned::Bytea(value) => value,
            QueryParamOwned::Json(value) => value,
        }
    }
}

fn decode_hex_param_value(value: &str) -> Result<Vec<u8>, anyhow::Error> {
    let trimmed = value.trim();
    let without_prefix = if let Some(stripped) = trimmed.strip_prefix("\\x") {
        stripped
    } else if let Some(stripped) = trimmed.strip_prefix("0x") {
        stripped
    } else {
        trimmed
    };
    Ok(hex::decode(without_prefix)?)
}

fn parse_query_params(
    values: &[Value],
    prefer_i32_for_small_ints: bool,
) -> Result<Vec<QueryParamOwned>, anyhow::Error> {
    let mut params = Vec::with_capacity(values.len());
    for value in values {
        match value {
            Value::Null => params.push(QueryParamOwned::Null(None)),
            Value::Bool(v) => params.push(QueryParamOwned::Bool(*v)),
            Value::Number(v) => {
                if let Some(i) = v.as_i64() {
                    if prefer_i32_for_small_ints {
                        if let Ok(i32_value) = i32::try_from(i) {
                            params.push(QueryParamOwned::Int32(i32_value));
                        } else {
                            params.push(QueryParamOwned::Int(i));
                        }
                    } else {
                        params.push(QueryParamOwned::Int(i));
                    }
                } else if let Some(f) = v.as_f64() {
                    params.push(QueryParamOwned::Float(f));
                } else {
                    return Err(anyhow::anyhow!("unsupported numeric parameter value"));
                }
            }
            Value::String(v) => params.push(QueryParamOwned::Text(v.clone())),
            Value::Array(array_value) => {
                params.push(QueryParamOwned::Json(Json(Value::Array(
                    array_value.clone(),
                ))));
            }
            Value::Object(map) => {
                let strict_typed_shape = map.len() == 2
                    && map.contains_key("param_type")
                    && map.contains_key("value")
                    && map.get("param_type").is_some_and(Value::is_string);
                if strict_typed_shape {
                    let type_name = map
                        .get("param_type")
                        .and_then(Value::as_str)
                        .map(|value| value.trim().to_ascii_lowercase())
                        .ok_or_else(|| {
                            anyhow::anyhow!(
                                "object params must use typed form: {{\"param_type\":\"...\",\"value\":...}}"
                            )
                        })?;
                    let typed_value = map.get("value").cloned().unwrap_or(Value::Null);
                    let parsed = match type_name.as_str() {
                        "null" => QueryParamOwned::Null(None),
                        "bool" | "boolean" => {
                            let value = typed_value.as_bool().ok_or_else(|| {
                                anyhow::anyhow!("typed param bool requires a boolean value")
                            })?;
                            QueryParamOwned::Bool(value)
                        }
                        "smallint" | "int2" | "i16" => {
                            let value = typed_value.as_i64().ok_or_else(|| {
                                anyhow::anyhow!("typed param int2 requires an integer value")
                            })?;
                            let value = i16::try_from(value).map_err(|_| {
                                anyhow::anyhow!(
                                    "typed param int2 is out of range for 16-bit integer"
                                )
                            })?;
                            QueryParamOwned::Int16(value)
                        }
                        "int" | "int4" | "integer" | "i32" => {
                            let value = typed_value.as_i64().ok_or_else(|| {
                                anyhow::anyhow!("typed param int4 requires an integer value")
                            })?;
                            let value = i32::try_from(value).map_err(|_| {
                                anyhow::anyhow!(
                                    "typed param int4 is out of range for 32-bit integer"
                                )
                            })?;
                            QueryParamOwned::Int32(value)
                        }
                        "bigint" | "int8" | "i64" => {
                            let value = typed_value.as_i64().ok_or_else(|| {
                                anyhow::anyhow!("typed param int8 requires an integer value")
                            })?;
                            QueryParamOwned::Int(value)
                        }
                        "float" | "float8" | "double" | "f64" => {
                            let value = typed_value.as_f64().ok_or_else(|| {
                                anyhow::anyhow!("typed param float8 requires a numeric value")
                            })?;
                            QueryParamOwned::Float(value)
                        }
                        "text" | "varchar" | "string" => {
                            let value = typed_value.as_str().ok_or_else(|| {
                                anyhow::anyhow!("typed param text/varchar requires a string value")
                            })?;
                            QueryParamOwned::Text(value.to_string())
                        }
                        "timestamptz" | "timestamp with time zone" => {
                            let value = typed_value.as_str().ok_or_else(|| {
                                anyhow::anyhow!(
                                    "typed param timestamptz requires an RFC3339 string value"
                                )
                            })?;
                            let value = DateTime::parse_from_rfc3339(value).map_err(|error| {
                                anyhow::anyhow!(
                                    "typed param timestamptz must be RFC3339: {}",
                                    error
                                )
                            })?;
                            QueryParamOwned::TimestampTz(value)
                        }
                        "timestamp" | "timestamp without time zone" => {
                            let value = typed_value.as_str().ok_or_else(|| {
                                anyhow::anyhow!(
                                    "typed param timestamp requires a YYYY-MM-DD HH:MM:SS string value"
                                )
                            })?;
                            let value = NaiveDateTime::parse_from_str(value, "%Y-%m-%d %H:%M:%S")
                                .map_err(|error| {
                                anyhow::anyhow!(
                                    "typed param timestamp must match YYYY-MM-DD HH:MM:SS: {}",
                                    error
                                )
                            })?;
                            QueryParamOwned::Timestamp(value)
                        }
                        "date" => {
                            let value = typed_value.as_str().ok_or_else(|| {
                                anyhow::anyhow!(
                                    "typed param date requires a YYYY-MM-DD string value"
                                )
                            })?;
                            let value =
                                NaiveDate::parse_from_str(value, "%Y-%m-%d").map_err(|error| {
                                    anyhow::anyhow!(
                                        "typed param date must match YYYY-MM-DD: {}",
                                        error
                                    )
                                })?;
                            QueryParamOwned::Date(value)
                        }
                        "time" => {
                            let value = typed_value.as_str().ok_or_else(|| {
                                anyhow::anyhow!("typed param time requires a HH:MM:SS string value")
                            })?;
                            let value =
                                NaiveTime::parse_from_str(value, "%H:%M:%S").map_err(|error| {
                                    anyhow::anyhow!(
                                        "typed param time must match HH:MM:SS: {}",
                                        error
                                    )
                                })?;
                            QueryParamOwned::Time(value)
                        }
                        "uuid" => {
                            let value = typed_value.as_str().ok_or_else(|| {
                                anyhow::anyhow!("typed param uuid requires a UUID string value")
                            })?;
                            let value = Uuid::parse_str(value).map_err(|error| {
                                anyhow::anyhow!("typed param uuid must be valid UUID: {}", error)
                            })?;
                            QueryParamOwned::Uuid(value)
                        }
                        "bytea" => {
                            let value = typed_value.as_str().ok_or_else(|| {
                                anyhow::anyhow!("typed param bytea requires a hex string value")
                            })?;
                            let decoded = decode_hex_param_value(value).map_err(|error| {
                                anyhow::anyhow!(
                                    "typed param bytea must be hex string (optionally prefixed with \\x): {}",
                                    error
                                )
                            })?;
                            QueryParamOwned::Bytea(decoded)
                        }
                        "json" | "jsonb" => QueryParamOwned::Json(Json(typed_value)),
                        _ => {
                            return Err(anyhow::anyhow!(
                                "unsupported typed param type: {}",
                                type_name
                            ));
                        }
                    };
                    params.push(parsed);
                } else {
                    params.push(QueryParamOwned::Json(Json(Value::Object(map.clone()))));
                }
            }
        }
    }
    Ok(params)
}

fn format_parameter_serialization_error(error: &tokio_postgres::Error) -> Option<anyhow::Error> {
    let message = error.to_string();
    if message
        .to_ascii_lowercase()
        .contains("error serializing parameter")
    {
        return Some(anyhow::anyhow!(
            "database query failed: {} (retrying with alternate integer parameter width may help)",
            message
        ));
    }
    None
}

async fn run_prepared_query(
    client: &deadpool_postgres::Client,
    wrapped_sql: &str,
    params: &[Value],
    timeout_ms: u64,
    prefer_i32_for_small_ints: bool,
) -> Result<Vec<tokio_postgres::Row>, anyhow::Error> {
    let owned_params = parse_query_params(params, prefer_i32_for_small_ints)?;
    let borrowed_params: Vec<&(dyn ToSql + Sync)> =
        owned_params.iter().map(QueryParamOwned::as_tosql).collect();
    let query_result = timeout(
        Duration::from_millis(timeout_ms),
        client.query(wrapped_sql, borrowed_params.as_slice()),
    )
    .await
    .map_err(|_| anyhow::anyhow!("query execution timed out"))?;

    match query_result {
        Ok(rows) => Ok(rows),
        Err(error) => {
            if let Some(serialization_error) = format_parameter_serialization_error(&error) {
                return Err(serialization_error);
            }
            Err(format_pg_query_error(error))
        }
    }
}

fn format_pg_db_error(db_error: &DbError) -> String {
    let mut parts = Vec::new();
    parts.push(format!(
        "database error [{}]: {}",
        db_error.code().code(),
        db_error.message()
    ));
    if let Some(detail) = db_error.detail() {
        if !detail.trim().is_empty() {
            parts.push(format!("detail: {}", detail));
        }
    }
    if let Some(hint) = db_error.hint() {
        if !hint.trim().is_empty() {
            parts.push(format!("hint: {}", hint));
        }
    }
    if let Some(position) = db_error.position() {
        parts.push(format!("position: {:?}", position));
    }
    parts.join(" | ")
}

fn format_pg_query_error(error: tokio_postgres::Error) -> anyhow::Error {
    if let Some(db_error) = error.as_db_error() {
        anyhow::anyhow!(format_pg_db_error(db_error))
    } else {
        anyhow::anyhow!("database query failed: {}", error)
    }
}

pub async fn run_query(
    pool: &Pool,
    sql: &str,
    params: &[Value],
    timeout_ms: u64,
    max_rows: usize,
) -> Result<DbQueryResult, anyhow::Error> {
    let trimmed_sql = sql.trim();
    if trimmed_sql.is_empty() {
        return Err(anyhow::anyhow!("query.sql cannot be empty"));
    }
    if trimmed_sql.contains(';') {
        return Err(anyhow::anyhow!(
            "query.sql cannot contain semicolons or multiple statements"
        ));
    }
    let start = Instant::now();
    let client = pool.get().await?;
    let wrapped_sql = format!(
        "SELECT row_to_json(simplevault_row) AS simplevault_row_json FROM ({}) AS simplevault_row",
        trimmed_sql
    );

    let db_rows = match run_prepared_query(&client, wrapped_sql.as_str(), params, timeout_ms, true)
        .await
    {
        Ok(rows) => rows,
        Err(error) => {
            let message = error.to_string().to_ascii_lowercase();
            if message.contains("error serializing parameter") {
                run_prepared_query(&client, wrapped_sql.as_str(), params, timeout_ms, false).await?
            } else {
                return Err(error);
            }
        }
    };
    let mut rows_json = Vec::with_capacity(db_rows.len());
    for row in db_rows {
        let Json(value): Json<Value> = row.try_get("simplevault_row_json").map_err(|error| {
            anyhow::anyhow!("failed to deserialize query result row: {}", error)
        })?;
        rows_json.push(value);
    }

    let mut columns = Vec::new();
    if let Some(Value::Object(first_row)) = rows_json.first() {
        for key in first_row.keys() {
            columns.push(DbQueryColumn {
                name: key.to_string(),
                db_type: None,
            });
        }
    }
    let ordered_names: Vec<String> = columns.iter().map(|column| column.name.clone()).collect();

    let row_count = rows_json.len();
    let truncated = row_count > max_rows;
    if truncated {
        rows_json.truncate(max_rows);
    }
    let rows = rows_json
        .iter()
        .map(|row_value| {
            let object = row_value.as_object().cloned().unwrap_or_default();
            ordered_names
                .iter()
                .map(|name| object.get(name).cloned().unwrap_or(Value::Null))
                .collect::<Vec<Value>>()
        })
        .collect::<Vec<Vec<Value>>>();
    let timing_ms = start.elapsed().as_millis();

    Ok(DbQueryResult {
        columns,
        rows,
        row_count,
        truncated,
        timing_ms,
    })
}

pub fn sanitize_connection_string(connection_string: &mut String) {
    connection_string.zeroize();
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn connection_string_hash_is_stable() {
        let a = connection_string_hash("postgres://user:pass@db.internal:5432/app");
        let b = connection_string_hash("postgres://user:pass@db.internal:5432/app");
        assert_eq!(a, b);
        assert_eq!(a.len(), 64);
    }

    #[test]
    fn parse_connection_targets_reads_host_and_port() {
        let targets =
            parse_connection_targets("postgres://user:pass@db.internal:5433/app").unwrap();
        assert_eq!(targets.len(), 1);
        assert_eq!(targets[0].0, "db.internal");
        assert_eq!(targets[0].1, 5433);
    }

    #[test]
    fn parse_connection_targets_defaults_port() {
        let targets = parse_connection_targets("postgres://user:pass@db.internal/app").unwrap();
        assert_eq!(targets[0].1, 5432);
    }

    #[test]
    fn parse_query_params_supports_common_typed_aliases() {
        let params = vec![
            json!({"param_type":"int2","value":7}),
            json!({"param_type":"smallint","value":8}),
            json!({"param_type":"timestamptz","value":"2025-01-01T12:30:45+00:00"}),
            json!({"param_type":"uuid","value":"123e4567-e89b-12d3-a456-426614174000"}),
            json!({"param_type":"date","value":"2025-01-01"}),
            json!({"param_type":"time","value":"12:30:45"}),
            json!({"param_type":"bytea","value":"\\x68656c6c6f"}),
            json!({"param_type":"jsonb","value":{"kind":"customer"}}),
        ];
        let parsed = parse_query_params(params.as_slice(), true).unwrap();
        assert_eq!(parsed.len(), 8);
    }

    #[test]
    fn parse_query_params_rejects_invalid_timestamptz() {
        let params = vec![json!({"param_type":"timestamptz","value":"not-a-timestamp"})];
        let error = parse_query_params(params.as_slice(), true).unwrap_err();
        assert!(error.to_string().contains("RFC3339"));
    }
}
