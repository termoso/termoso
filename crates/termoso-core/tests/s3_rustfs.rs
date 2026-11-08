//! S3 client against a real S3-compatible server (RustFS / MinIO) at
//! `TERMOSO_TEST_S3_ENDPOINT` (default `http://127.0.0.1:9000`) with
//! `TERMOSO_TEST_S3_ACCESS_KEY` / `TERMOSO_TEST_S3_SECRET_KEY` (default
//! `minioadmin`) and an existing bucket `TERMOSO_TEST_S3_BUCKET` (default
//! `termoso-core-test-s3`). Skips when the endpoint is unreachable unless
//! `TERMOSO_TEST_REQUIRE_SERVICES` is set.

use std::time::Duration;

use termoso_core::error::CoreError;
use termoso_core::remote::{RemoteFs, RemoteProtocol};
use termoso_core::s3::{S3, S3Config};
use termoso_core::sftp::{EntryKind, OpenMode, TransferOptions};

fn endpoint() -> String {
    std::env::var("TERMOSO_TEST_S3_ENDPOINT").unwrap_or_else(|_| "http://127.0.0.1:9000".into())
}

async fn reachable(url: &str) -> bool {
    let u = url::Url::parse(url).expect("endpoint url");
    let hp = format!(
        "{}:{}",
        u.host_str().unwrap_or("127.0.0.1"),
        u.port_or_known_default().unwrap_or(80)
    );
    let ok = tokio::time::timeout(Duration::from_secs(2), tokio::net::TcpStream::connect(hp))
        .await
        .is_ok_and(|r| r.is_ok());
    if !ok {
        if std::env::var("TERMOSO_TEST_REQUIRE_SERVICES").is_ok() {
            panic!("S3 storage unavailable at {url}");
        }
        eprintln!("S3 storage unavailable at {url}: skipping");
    }
    ok
}

/// A client rooted at a fresh prefix of the test bucket.
async fn client() -> Option<S3> {
    let endpoint = endpoint();
    if !reachable(&endpoint).await {
        return None;
    }
    let cfg = S3Config {
        endpoint,
        bucket: std::env::var("TERMOSO_TEST_S3_BUCKET")
            .unwrap_or_else(|_| "termoso-core-test-s3".into()),
        prefix: format!("run-{}", uuid::Uuid::new_v4().simple()),
        access_key: std::env::var("TERMOSO_TEST_S3_ACCESS_KEY")
            .unwrap_or_else(|_| "minioadmin".into()),
        secret_key: std::env::var("TERMOSO_TEST_S3_SECRET_KEY")
            .unwrap_or_else(|_| "minioadmin".into()),
        spool_dir: Some(std::env::temp_dir()),
        ..S3Config::default()
    };
    Some(S3::connect(cfg).await.expect("connect"))
}

#[tokio::test]
async fn folders_files_and_listing() {
    let Some(s3) = client().await else { return };
    assert_eq!(s3.protocol(), RemoteProtocol::S3);
    assert!(s3.list("/").await.unwrap().is_empty());

    s3.mkdir("/docs").await.unwrap();
    s3.mkdir_all("/docs/deep/er").await.unwrap();
    s3.write("/docs/a.txt", b"hello").await.unwrap();
    s3.write("/docs/deep/b.txt", b"world!").await.unwrap();
    s3.write("/top.bin", &[0u8; 10]).await.unwrap();

    let root = s3.list("/").await.unwrap();
    let names: Vec<_> = root.iter().map(|e| (e.name.as_str(), e.kind)).collect();
    assert_eq!(
        names,
        vec![("docs", EntryKind::Dir), ("top.bin", EntryKind::File)]
    );

    let docs = s3.list("/docs").await.unwrap();
    let names: Vec<_> = docs.iter().map(|e| e.name.as_str()).collect();
    assert_eq!(names, vec!["deep", "a.txt"]);
    assert_eq!(docs[1].size, Some(5));
    assert!(docs[1].mtime.is_some());

    // An empty folder exists only through its marker.
    assert!(s3.list("/docs/deep/er").await.unwrap().is_empty());
    assert_eq!(s3.stat("/docs/deep/er").await.unwrap().kind, EntryKind::Dir);
    // A prefix without a marker is a folder too.
    assert_eq!(s3.stat("/docs/deep").await.unwrap().kind, EntryKind::Dir);
    assert!(matches!(
        s3.list("/nope").await,
        Err(CoreError::NotFound(_))
    ));
    assert!(matches!(
        s3.stat("/nope").await,
        Err(CoreError::NotFound(_))
    ));
    assert!(!s3.exists("/docs/zzz").await.unwrap());
    assert!(matches!(s3.mkdir("/docs").await, Err(CoreError::S3 { .. })));

    assert_eq!(s3.read("/docs/a.txt").await.unwrap(), b"hello");

    s3.rename("/docs/a.txt", "/docs/renamed.txt").await.unwrap();
    assert!(!s3.exists("/docs/a.txt").await.unwrap());
    assert_eq!(s3.read("/docs/renamed.txt").await.unwrap(), b"hello");
    assert!(matches!(
        s3.rename("/docs/renamed.txt", "/top.bin").await,
        Err(CoreError::S3 { .. })
    ));

    s3.copy("/docs/deep", "/copy").await.unwrap();
    assert_eq!(s3.read("/copy/b.txt").await.unwrap(), b"world!");
    assert_eq!(s3.stat("/copy/er").await.unwrap().kind, EntryKind::Dir);

    s3.rename("/docs", "/moved").await.unwrap();
    assert!(!s3.exists("/docs").await.unwrap());
    assert_eq!(s3.read("/moved/deep/b.txt").await.unwrap(), b"world!");

    assert!(matches!(
        s3.remove_dir("/moved").await,
        Err(CoreError::S3 { .. })
    ));
    s3.remove_dir("/moved/deep/er").await.unwrap();
    assert!(!s3.exists("/moved/deep/er").await.unwrap());
    s3.remove_file("/top.bin").await.unwrap();
    assert!(matches!(
        s3.remove_file("/top.bin").await,
        Err(CoreError::NotFound(_))
    ));
    assert!(matches!(
        s3.chmod("/moved", 0o755).await,
        Err(CoreError::S3 { .. })
    ));

    let cancel = tokio_util::sync::CancellationToken::new();
    s3.remove_dir_all("/moved", &cancel).await.unwrap();
    s3.remove_dir_all("/copy", &cancel).await.unwrap();
    assert!(s3.list("/").await.unwrap().is_empty());
}

#[tokio::test]
async fn transfers_and_open_file() {
    let Some(s3) = client().await else { return };
    let dir = tempfile::tempdir().unwrap();
    let src = dir.path().join("big.bin");
    let data: Vec<u8> = (0..(20 * 1024 * 1024 + 123))
        .map(|i| (i % 251) as u8)
        .collect();
    std::fs::write(&src, &data).unwrap();

    let seen = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
    let s = seen.clone();
    let opts = TransferOptions {
        progress: Some(std::sync::Arc::new(move |p| s.lock().unwrap().push(p.done))),
        ..TransferOptions::default()
    };
    // Above the multipart threshold: goes by parts.
    assert_eq!(
        s3.upload(&src, "/up/big.bin", &opts).await.unwrap(),
        data.len() as u64
    );
    assert_eq!(
        seen.lock().unwrap().last().copied(),
        Some(data.len() as u64)
    );
    let e = s3.stat("/up/big.bin").await.unwrap();
    assert_eq!(e.size, Some(data.len() as u64));

    let dst = dir.path().join("down.bin");
    let moved = s3
        .download("/up/big.bin", &dst, &TransferOptions::default())
        .await
        .unwrap();
    assert_eq!(moved, data.len() as u64);
    assert_eq!(std::fs::read(&dst).unwrap(), data);

    // Resume continues from the bytes already there.
    std::fs::write(&dst, &data[..1000]).unwrap();
    let opts = TransferOptions {
        resume: true,
        ..TransferOptions::default()
    };
    let moved = s3.download("/up/big.bin", &dst, &opts).await.unwrap();
    assert_eq!(moved, data.len() as u64 - 1000);
    assert_eq!(std::fs::read(&dst).unwrap(), data);

    // Small upload: a single PutObject.
    let small = dir.path().join("small.txt");
    std::fs::write(&small, b"tiny").unwrap();
    s3.upload(&small, "/up/small.txt", &TransferOptions::default())
        .await
        .unwrap();
    assert_eq!(s3.read("/up/small.txt").await.unwrap(), b"tiny");

    // Ranged reads through an open file.
    let f = s3.open_file("/up/big.bin", OpenMode::Read).await.unwrap();
    assert_eq!(f.size().await.unwrap(), data.len() as u64);
    assert_eq!(f.read_at(1000, 10).await.unwrap(), &data[1000..1010]);
    assert!(
        f.read_at(data.len() as u64 + 5, 10)
            .await
            .unwrap()
            .is_empty()
    );
    assert!(f.write_at(0, b"x").await.is_err());
    f.close().await.unwrap();

    // Writes spool locally and land on close.
    let f = s3.open_file("/up/new.txt", OpenMode::Write).await.unwrap();
    f.write_at(0, b"abcdef").await.unwrap();
    f.write_at(2, b"XY").await.unwrap();
    f.close().await.unwrap();
    assert_eq!(s3.read("/up/new.txt").await.unwrap(), b"abXYef");

    let f = s3
        .open_file("/up/new.txt", OpenMode::ReadWrite)
        .await
        .unwrap();
    assert_eq!(f.read_at(0, 6).await.unwrap(), b"abXYef");
    f.truncate(2).await.unwrap();
    f.sync().await.unwrap();
    f.close().await.unwrap();
    assert_eq!(s3.read("/up/new.txt").await.unwrap(), b"ab");

    assert!(matches!(
        s3.download("/up", &dst, &TransferOptions::default()).await,
        Err(CoreError::S3 { .. })
    ));
    assert!(matches!(
        s3.download("/up/none", &dst, &TransferOptions::default())
            .await,
        Err(CoreError::NotFound(_))
    ));

    s3.remove_dir_all("/up", &tokio_util::sync::CancellationToken::new())
        .await
        .unwrap();
    assert!(s3.list("/").await.unwrap().is_empty());
}

#[tokio::test]
async fn bad_credentials_are_an_s3_error() {
    let endpoint = endpoint();
    if !reachable(&endpoint).await {
        return;
    }
    let err = S3::connect(S3Config {
        endpoint,
        bucket: "termoso-core-test-s3".into(),
        access_key: "nobody".into(),
        secret_key: "wrong".into(),
        ..S3Config::default()
    })
    .await
    .expect_err("rejected");
    match err {
        CoreError::S3 { status, message } => {
            assert_eq!(status, Some(403));
            assert!(message.contains("access key"), "{message}");
        }
        e => panic!("{e:?}"),
    }
}
