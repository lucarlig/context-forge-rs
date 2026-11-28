// SPDX-License-Identifier: Apache-2.0

use std::{fs, process::Command};

#[test]
fn migrations_use_dotenv_and_process_database_precedence() {
    let directory = std::env::temp_dir().join(format!("context-forge-{}", uuid::Uuid::new_v4()));
    fs::create_dir(&directory).unwrap();
    let dotenv = "FILE_DATABASE=deployment.db\ndatabase_url=sqlite:///${FILE_DATABASE}\n";
    fs::write(directory.join(".env"), dotenv).unwrap();
    let migrate = || {
        let mut command = Command::new(env!("CARGO_BIN_EXE_context-forge-rs"));
        command.env_clear().current_dir(&directory).arg("migrate");
        command
    };
    let file = migrate().output().unwrap();
    assert!(
        file.status.success(),
        "{}",
        String::from_utf8_lossy(&file.stderr)
    );
    assert!(directory.join("deployment.db").is_file());
    let process = migrate()
        .env("DATABASE_URL", "sqlite:///process.db")
        .output()
        .unwrap();
    assert!(
        process.status.success(),
        "{}",
        String::from_utf8_lossy(&process.stderr)
    );
    assert!(directory.join("process.db").is_file());
    assert_eq!(fs::read_to_string(directory.join(".env")).unwrap(), dotenv);
    fs::remove_dir_all(directory).unwrap();
}

#[test]
fn config_validation_selects_one_file_and_redacts_invalid_values() {
    let directory = std::env::temp_dir().join(format!("context-forge-{}", uuid::Uuid::new_v4()));
    fs::create_dir(&directory).unwrap();
    let command = || {
        let mut command = Command::new(env!("CARGO_BIN_EXE_context-forge-rs"));
        command.env_clear().current_dir(&directory);
        command
    };
    let path = directory.join("selected.env");
    fs::write(directory.join(".env"), "DCR_DEFAULT_SCOPES=invalid\n").unwrap();
    let generated = command()
        .args(["init-secrets", "--patch-env", "selected.env"])
        .output()
        .unwrap();
    assert!(generated.status.success());
    let baseline = fs::read_to_string(&path).unwrap();
    fs::write(&path, format!("{baseline}PORT=invalid\n")).unwrap();

    let valid = command()
        .args(["--validate-config", "selected.env"])
        .env("MCG_PORT", "4545")
        .output()
        .unwrap();
    assert!(valid.status.success());

    let private_input = "redaction-fixture-value";
    fs::write(
        &path,
        format!("{baseline}OAUTH_REDIRECT_ALLOWED_ORIGIN=http://{private_input}.test/\n"),
    )
    .unwrap();
    let invalid = command()
        .args(["--validate-config", "selected.env"])
        .output()
        .unwrap();
    assert_eq!(invalid.status.code(), Some(1));
    let errors = String::from_utf8(invalid.stderr).unwrap();
    assert!(errors.contains("oauth_redirect_allowed_origin"));
    assert!(!errors.contains(private_input));
    fs::remove_dir_all(directory).unwrap();
}
