// SPDX-License-Identifier: Apache-2.0

use std::{fs, io::Read, process::Command};

use serde_json::Value;
use uuid::Uuid;
use zip::ZipArchive;

#[test]
fn support_bundle_keeps_the_log_tail_and_redacts_credentials() {
    let directory = std::env::temp_dir().join(format!("context-forge-{}", Uuid::new_v4()));
    let secret = format!("fixture-{}", Uuid::new_v4());
    let encoded = format!("fixture-{}", Uuid::new_v4());
    fs::create_dir_all(directory.join("logs/nested")).unwrap();
    fs::write(
        directory.join(".env"),
        format!(
            "LOG_FILE=nested/diagnostics.log\nJWT_SECRET_KEY={secret}\n\
             DATABASE_URL=postgresql://gateway:{secret}@db.example.test/forge\n\
             SIEM_DESTINATIONS='[{{\"endpoint\":\"https://example.test\",\"token\":\"{secret}\"}}]'\n"
        ),
    )
    .unwrap();
    fs::write(
        directory.join("logs/nested/diagnostics.log"),
        format!(
            "removed line\n{{\"authorization\":\"Basic {encoded}\",\"status\":200}}\nlast line\n"
        ),
    )
    .unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_context-forge-rs"))
        .current_dir(&directory)
        .env_clear()
        .env("BUNDLE_EXAMPLE_API_KEY", &secret)
        .env("EXAMPLE_DIAGNOSTIC_TEXT", format!("a copy of {secret}"))
        .args([
            "--support-bundle",
            "--output-dir",
            "output",
            "--log-lines",
            "2",
        ])
        .output()
        .unwrap();
    assert!(output.status.success());
    let path = fs::read_dir(directory.join("output"))
        .unwrap()
        .next()
        .unwrap()
        .unwrap()
        .path();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }
    let mut bundle = ZipArchive::new(fs::File::open(path).unwrap()).unwrap();
    assert_eq!(bundle.len(), 7);
    for index in 0..bundle.len() {
        let mut entry = bundle.by_index(index).unwrap();
        let mut text = String::new();
        entry.read_to_string(&mut text).unwrap();
        assert!(!text.contains(&secret));
        assert!(!text.contains(&encoded));
        match entry.name().unwrap().as_ref() {
            "settings.json" => {
                let settings: Value = serde_json::from_str(&text).unwrap();
                assert!(settings.get("jwt_secret_key").is_none());
                assert_eq!(settings["siem_destinations"][0]["token"], "*****");
                assert_eq!(
                    settings["database_url"],
                    "postgresql://gateway:*****@db.example.test/forge"
                );
            }
            "environment.json" => {
                let environment: Value = serde_json::from_str(&text).unwrap();
                assert_eq!(environment["BUNDLE_EXAMPLE_API_KEY"], "*****");
                assert_eq!(environment["EXAMPLE_DIAGNOSTIC_TEXT"], "a copy of *****");
            }
            "logs/diagnostics.log" => {
                assert!(text.starts_with("[Showing last 2 lines]\n"));
                assert!(!text.contains("removed line"));
                let line: Value = serde_json::from_str(text.lines().nth(1).unwrap()).unwrap();
                assert_eq!(line["authorization"], "*****");
                assert_eq!(line["status"], 200);
                assert!(text.ends_with("last line\n"));
            }
            unexpected if unexpected.starts_with("logs/") => panic!("unexpected log path"),
            _ => {}
        }
    }
    assert!(
        bundle
            .file_names()
            .any(|name| name.is_ok_and(|name| name == "logs/diagnostics.log"))
    );
    drop(bundle);
    fs::remove_dir_all(directory).unwrap();
}
