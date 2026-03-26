use std::net::TcpListener;
use std::time::{SystemTime, UNIX_EPOCH};

use postgresql_embedded::{PostgreSQL, SettingsBuilder, VersionReq};

const TEST_PG_HOST: &str = "127.0.0.1";
const TEST_PG_USERNAME: &str = "postgres";
const TEST_PG_PASSWORD: &str = "postgres";
const ZONKY_RELEASES_URL: &str = "https://github.com/zonkyio/embedded-postgres-binaries";

pub struct TestPg;

impl TestPg {
    pub fn new() -> Self {
        Self
    }

    pub async fn create(
        &self,
        migration_sql: &str,
    ) -> Result<(PostgreSQL, String), anyhow::Error> {
        let port = allocate_free_port()?;
        let database_name = format!(
            "simplevault_test_{}_{}",
            SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos(),
            rand::random::<u32>()
        );

        let settings = SettingsBuilder::new()
            .releases_url(ZONKY_RELEASES_URL)
            .version(VersionReq::parse("=16.10.0")?)
            .host(TEST_PG_HOST)
            .port(port)
            .username(TEST_PG_USERNAME)
            .password(TEST_PG_PASSWORD)
            .temporary(true)
            .build();

        let connection_string = settings.url(&database_name);
        let mut postgresql = PostgreSQL::new(settings);
        postgresql.setup().await?;
        postgresql.start().await?;
        postgresql.create_database(&database_name).await?;

        run_migration(&connection_string, migration_sql).await?;

        Ok((postgresql, connection_string))
    }
}

impl Default for TestPg {
    fn default() -> Self {
        Self::new()
    }
}

fn allocate_free_port() -> Result<u16, anyhow::Error> {
    let listener = TcpListener::bind((TEST_PG_HOST, 0))?;
    let port = listener.local_addr()?.port();
    drop(listener);
    Ok(port)
}

async fn run_migration(connection_string: &str, migration_sql: &str) -> Result<(), anyhow::Error> {
    if migration_sql.trim().is_empty() {
        return Ok(());
    }
    let (client, connection) = tokio_postgres::connect(connection_string, tokio_postgres::NoTls).await?;
    tokio::spawn(async move {
        let _ = connection.await;
    });
    client.batch_execute(migration_sql).await?;
    Ok(())
}
