// Test-only disposable PostgreSQL fixture for the Node Worker harness.
// It never reads DATABASE_URL and only listens on localhost.
use postgresql_embedded::blocking::PostgreSQL;

fn main() {
    let mut pg = PostgreSQL::default();
    pg.setup().expect("embedded pg setup");
    pg.start().expect("embedded pg start");
    let _ = pg.create_database("worker_auth_node");
    let url = pg.settings().url("worker_auth_node");
    assert!(url.contains("localhost") || url.contains("127.0.0.1"));
    std::fs::write("/tmp/g1154-pg-url", &url).expect("write local test url");
    eprintln!("local test pg ready");
    loop {
        std::thread::sleep(std::time::Duration::from_secs(3600));
    }
}
