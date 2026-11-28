// SPDX-License-Identifier: Apache-2.0

use std::{env::consts, path::Path};

use jiff::Timestamp;
use serde_json::{Value, json};
use sysinfo::{Disks, Pid, ProcessRefreshKind, ProcessesToUpdate, System};

#[derive(Default)]
pub(crate) struct Metrics {
    system: System,
    disks: Disks,
}

pub(crate) fn platform() -> String {
    let name = System::name().unwrap_or_else(|| consts::OS.to_owned());
    let kernel = System::kernel_version().unwrap_or_default();
    format!("{name} {kernel} ({})", System::cpu_arch())
}

impl Metrics {
    pub(crate) fn sample(&mut self) -> Value {
        if !sysinfo::IS_SUPPORTED_SYSTEM {
            return json!({});
        }

        let pid = Pid::from_u32(std::process::id());
        let pids = [pid];
        let processes = ProcessesToUpdate::Some(&pids);
        let refresh = ProcessRefreshKind::nothing()
            .with_cpu()
            .with_memory()
            .with_tasks();
        if self.system.cpus().is_empty() {
            self.system.refresh_cpu_all();
            self.system
                .refresh_processes_specifics(processes, true, refresh);
            std::thread::sleep(sysinfo::MINIMUM_CPU_UPDATE_INTERVAL);
        }
        self.system.refresh_memory();
        self.system.refresh_cpu_all();
        self.system
            .refresh_processes_specifics(processes, true, refresh);
        self.disks.refresh(true);

        let boot = i64::try_from(System::boot_time())
            .ok()
            .and_then(|seconds| Timestamp::from_second(seconds).ok());
        let load = System::load_average();
        let load = if cfg!(windows) {
            json!([null, null, null])
        } else {
            json!([round(load.one), round(load.five), round(load.fifteen)])
        };
        let root = if cfg!(windows) {
            let drive = std::env::var("SystemDrive").unwrap_or_else(|_| "C:".to_owned());
            format!("{drive}\\")
        } else {
            "/".to_owned()
        };
        let disk = self
            .disks
            .list()
            .iter()
            .find(|disk| disk.mount_point() == Path::new(&root));
        let process = self.system.process(pid);
        let mebibytes = |bytes: u64| bytes as f64 / 1_048_576.0;
        let gibibytes = |bytes: u64| round(bytes as f64 / 1_073_741_824.0);
        json!({
            "boot_time":boot.map(|time| time.to_string()),
            "cpu_percent":round(f64::from(self.system.global_cpu_usage())),
            "cpu_count":self.system.cpus().len(),
            "cpu_freq_mhz":self.system.cpus().first().map(|cpu| cpu.frequency()).filter(|freq| *freq > 0),
            "load_avg":load,
            "mem_total_mb":mebibytes(self.system.total_memory()).round() as u64,
            "mem_used_mb":mebibytes(self.system.used_memory()).round() as u64,
            "swap_total_mb":mebibytes(self.system.total_swap()).round() as u64,
            "swap_used_mb":mebibytes(self.system.used_swap()).round() as u64,
            "disk_total_gb":disk.map(|disk| gibibytes(disk.total_space())),
            "disk_used_gb":disk.map(|disk| gibibytes(disk.total_space().saturating_sub(disk.available_space()))),
            "process":{
                "pid":pid.as_u32(),
                "threads":process.and_then(|process| process.tasks()).map(|tasks| tasks.len() + 1),
                "rss_mb":process.map(|process| round(mebibytes(process.memory()))),
                "vms_mb":process.map(|process| round(mebibytes(process.virtual_memory()))),
                "open_fds":process.and_then(|process| process.open_files()),
                "proc_cpu_percent":process.map(|process| round(f64::from(process.cpu_usage()))),
            },
        })
    }
}

fn round(value: f64) -> f64 {
    (value * 100.0).round() / 100.0
}
