//! System information: CPU, RAM and, when nvidia-smi exists, the GPU.
use sysinfo::System;

#[cfg_attr(not(windows), allow(dead_code))]
pub fn available_ram() -> u64 {
    let mut s = System::new();
    s.refresh_memory();
    s.available_memory()
}

pub fn parse_nvidia_smi(s: &str) -> Vec<String> {
    s.lines()
        .filter_map(|l| {
            let p: Vec<&str> = l.split(',').map(str::trim).collect();
            (p.len() == 5).then(|| format!("{}: {}% load, {} C, {}/{} MiB VRAM", p[0], p[1], p[2], p[3], p[4]))
        })
        .collect()
}

pub fn print() {
    let mut s = System::new_all();
    std::thread::sleep(sysinfo::MINIMUM_CPU_UPDATE_INTERVAL);
    s.refresh_cpu_usage();
    s.refresh_memory();
    println!("OS:   {}", System::long_os_version().unwrap_or_else(|| "unknown".into()));
    let brand = s.cpus().first().map(|c| c.brand().trim().to_string()).unwrap_or_default();
    println!("CPU:  {brand} ({} threads) at {:.0}% load", s.cpus().len(), s.global_cpu_usage());
    println!("RAM:  {} used of {}", crate::ui::fmt_bytes(s.used_memory()), crate::ui::fmt_bytes(s.total_memory()));
    let q = ["--query-gpu=name,utilization.gpu,temperature.gpu,memory.used,memory.total", "--format=csv,noheader,nounits"];
    match super::run("nvidia-smi", &q) {
        Ok(o) => parse_nvidia_smi(&o).into_iter().for_each(|l| println!("GPU:  {l}")),
        Err(_) => println!("GPU:  no NVIDIA tools found"),
    }
    println!("Networks:");
    for i in crate::engine::list_interfaces() {
        println!("  {} {}", i.name, i.ip);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nvidia_smi_parsing() {
        let v = parse_nvidia_smi("RTX 4070, 35, 60, 2000, 12282\nbad line\n");
        assert_eq!(v, vec!["RTX 4070: 35% load, 60 C, 2000/12282 MiB VRAM"]);
    }
}
