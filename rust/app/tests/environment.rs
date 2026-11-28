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
