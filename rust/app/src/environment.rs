// SPDX-License-Identifier: Apache-2.0

use std::{collections::HashMap, env, ffi::OsString, fs, io, path::Path, sync::OnceLock};

use zeroize::Zeroizing;

use crate::env_file::EnvFile;

type FileValues = HashMap<String, Zeroizing<String>>;
static FILE_ENVIRONMENT: OnceLock<Environment> = OnceLock::new();

pub(crate) struct Environment {
    process_names: HashMap<String, String>,
    file_values: FileValues,
    listener_values: FileValues,
}

impl Environment {
    pub(crate) fn from_file(path: &Path) -> io::Result<Self> {
        Self::read(path, None)
    }

    fn read(default_path: &Path, explicit: Option<&Path>) -> io::Result<Self> {
        let mut process_names = HashMap::new();
        for (name, _) in env::vars_os() {
            if let Ok(name) = name.into_string() {
                let canonical = name.to_ascii_uppercase();
                if canonical == name {
                    process_names.insert(canonical, name);
                } else {
                    process_names.entry(canonical).or_insert(name);
                }
            }
        }

        let default_contents = optional_contents(default_path)?;
        let defaults =
            EnvFile::parse(&default_contents).map_err(|error| file_error(default_path, error))?;
        let listener_values = defaults
            .variables()
            .filter_map(|(name, value)| {
                let upper = name.to_ascii_uppercase();
                matches!(upper.as_str(), "HOST" | "MCG_HOST" | "PORT" | "MCG_PORT")
                    .then(|| (upper, Zeroizing::new(value.to_owned())))
            })
            .collect();
        let file_values = if let Some(path) = explicit {
            let contents =
                Zeroizing::new(fs::read_to_string(path).map_err(|error| file_error(path, error))?);
            let explicit = EnvFile::parse_with(&contents, true, process_text)
                .map_err(|error| file_error(path, error))?;
            let imported: HashMap<_, _> = explicit.variables().collect();
            let defaults = EnvFile::parse_with(&default_contents, false, |name| {
                process_text(name).or_else(|| {
                    imported
                        .get(name)
                        .map(|value| Zeroizing::new((*value).to_owned()))
                })
            })
            .map_err(|error| file_error(default_path, error))?;
            collected(defaults.variables().chain(explicit.variables()))
        } else {
            collected(defaults.variables())
        };
        Ok(Self {
            process_names,
            file_values,
            listener_values,
        })
    }

    fn process_value(&self, name: &str) -> Option<OsString> {
        self.process_names.get(name).and_then(env::var_os)
    }

    pub(crate) fn var_os(&self, name: &str) -> Option<OsString> {
        self.process_value(name).or_else(|| {
            self.file_values
                .get(name)
                .map(|value| value.as_str().into())
        })
    }

    pub(crate) fn overridden_file_value(&self, name: &str) -> Option<&str> {
        self.process_names.get(name)?;
        self.file_values.get(name).map(|value| value.as_str())
    }

    pub(crate) fn listener(&self, primary: &str, legacy: &str) -> Option<OsString> {
        self.process_value(primary)
            .or_else(|| self.process_value(legacy))
            .or_else(|| {
                self.listener_values
                    .get(primary)
                    .or_else(|| self.listener_values.get(legacy))
                    .map(|value| value.as_str().into())
            })
    }
}

pub fn load(explicit: Option<&Path>) -> io::Result<()> {
    let environment = Environment::read(Path::new(".env"), explicit)?;
    FILE_ENVIRONMENT
        .set(environment)
        .map_err(|_| io::Error::other("configuration files already loaded"))
}

pub(crate) fn var_os(name: &str) -> Option<OsString> {
    match FILE_ENVIRONMENT.get() {
        Some(environment) => environment.var_os(name),
        None => env::var_os(name),
    }
}

pub(crate) fn var(name: &str) -> Result<String, env::VarError> {
    var_os(name)
        .ok_or(env::VarError::NotPresent)?
        .into_string()
        .map_err(env::VarError::NotUnicode)
}

pub(crate) fn listener(primary: &str, legacy: &str) -> Result<Option<String>, env::VarError> {
    let selected = match FILE_ENVIRONMENT.get() {
        Some(environment) => environment.listener(primary, legacy),
        None => env::var_os(primary).or_else(|| env::var_os(legacy)),
    };
    selected
        .map(|value| value.into_string().map_err(env::VarError::NotUnicode))
        .transpose()
}

fn optional_contents(path: &Path) -> io::Result<Zeroizing<String>> {
    match fs::metadata(path) {
        Ok(metadata) if metadata.is_file() => fs::read_to_string(path)
            .map(Zeroizing::new)
            .map_err(|error| file_error(path, error)),
        Ok(_) => Ok(Zeroizing::new(String::new())),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(Zeroizing::new(String::new())),
        Err(error) => Err(file_error(path, error)),
    }
}

fn collected<'a>(assignments: impl Iterator<Item = (&'a str, &'a str)>) -> FileValues {
    assignments
        .map(|(name, value)| (name.to_ascii_uppercase(), Zeroizing::new(value.to_owned())))
        .collect()
}

fn process_text(name: &str) -> Option<Zeroizing<String>> {
    env::var(name).ok().map(Zeroizing::new)
}

fn file_error(path: &Path, error: io::Error) -> io::Error {
    io::Error::new(error.kind(), format!("{}: {error}", path.display()))
}
