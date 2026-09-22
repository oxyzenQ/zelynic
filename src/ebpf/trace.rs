// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only

//! Verbose trace line formatters — the `-v` diagnostic contract.
//!
//! NIGHT-boost-6: `-v` is load-bearing debugging infrastructure, not a
//! garnish. Every loader path (limiter + observer) now traces what an
//! eBPF hacker actually needs at attach time — object size, kernel
//! release, load/attach timings, and the loaded map inventory — the
//! facts `bpftool` would show, without leaving the command that failed.
//! All output rides stderr through [`eprintln_safe!`], so `--print-json`
//! stdout stays machine-parseable.
//!
//! Every line is a pure function so the exact wording is unit-pinned
//! below (the NIGHT-hunt-9 discipline: the trace surface is a stable
//! contract users can grep and scripts can rely on, not ad-hoc
//! eprintln strings scattered through the attach paths).

use aya::maps::{Map, MapInfo, MapType};
use std::time::Duration;

/// Milliseconds with one decimal ("8.2") — the one duration shape
/// every load/attach timing prints through, so two sites can never
/// drift into different renderings of the same measurement.
pub fn ms(d: Duration) -> String {
    format!("{:.1}", d.as_secs_f64() * 1000.0)
}

/// The kernel line: `[limiter] kernel 6.8.0-45-generic`.
///
/// Printed before any load work — the release decides bpf_link
/// support, verifier features, and cgroup v2 shape, so a bug report
/// that starts with this line needs no follow-up uname.
pub fn kernel_line(tag: &str, release: &str) -> String {
    format!("[{tag}] kernel {release}")
}

/// The load summary: `[limiter] object loaded: 2 programs, 9 maps in 8.2ms`.
///
/// Program and map counts come from the loader's own view of the
/// object (`Ebpf::programs()` / `Ebpf::maps()`), so a mismatch with
/// the pinned state names its side of the disagreement immediately.
pub fn load_line(tag: &str, programs: usize, maps: usize, elapsed: Duration) -> String {
    let prog_unit = if programs == 1 { "program" } else { "programs" };
    let map_unit = if maps == 1 { "map" } else { "maps" };
    format!(
        "[{tag}] object loaded: {programs} {prog_unit}, {maps} {map_unit} in {}ms",
        ms(elapsed)
    )
}

/// One loaded map's inventory line:
/// `[limiter] map cgroup_policy_dl: id 123, hash map, key 4B, value 16B, max_entries 1024`.
///
/// Field names mirror `bpftool map show` vocabulary (id, key, value,
/// max_entries) so a trace line can be cross-checked against
/// `bpftool map show id <id>` without translation. `kind` comes from
/// [`map_type_name`].
pub fn map_line(
    tag: &str,
    name: &str,
    id: u32,
    kind: &str,
    key_size: u32,
    value_size: u32,
    max_entries: u32,
) -> String {
    format!(
        "[{tag}] map {name}: id {id}, {kind} map, key {key_size}B, value {value_size}B, max_entries {max_entries}"
    )
}

/// Kernel [`MapInfo`] for one loaded map.
///
/// aya 0.13 keeps `info()` on `MapData` and the `Map` enum's inner
/// `MapData` is private, so this is the one de-enumerating match —
/// exhaustive by construction (every variant carries a `MapData`),
/// and a future aya that grows a variant fails the build right
/// here instead of silently hiding it from the -v inventory.
pub fn map_info(map: &Map) -> Option<MapInfo> {
    let data = match map {
        Map::Array(d)
        | Map::BloomFilter(d)
        | Map::CpuMap(d)
        | Map::DevMap(d)
        | Map::DevMapHash(d)
        | Map::HashMap(d)
        | Map::LpmTrie(d)
        | Map::LruHashMap(d)
        | Map::PerCpuArray(d)
        | Map::PerCpuHashMap(d)
        | Map::PerCpuLruHashMap(d)
        | Map::PerfEventArray(d)
        | Map::ProgramArray(d)
        | Map::Queue(d)
        | Map::RingBuf(d)
        | Map::SockHash(d)
        | Map::SockMap(d)
        | Map::Stack(d)
        | Map::StackTraceMap(d)
        | Map::Unsupported(d)
        | Map::XskMap(d) => d,
    };
    data.info().ok()
}

/// aya's [`MapType`] in bpftool's vocabulary. The enum is
/// `#[non_exhaustive]`; unknown variants render as "other" rather
/// than failing the whole inventory over a naming detail.
pub fn map_type_name(t: MapType) -> &'static str {
    match t {
        MapType::Hash => "hash",
        MapType::Array => "array",
        MapType::PerCpuHash => "percpu hash",
        MapType::PerCpuArray => "percpu array",
        MapType::LruHash => "lru hash",
        MapType::LruPerCpuHash => "lru percpu hash",
        MapType::StackTrace => "stack trace",
        _ => "other",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The timing shape is one decimal, milliseconds — the pinned
    /// contract every attach path prints through.
    #[test]
    fn ms_renders_one_decimal() {
        assert_eq!(ms(Duration::from_micros(8_234)), "8.2");
        assert_eq!(ms(Duration::from_millis(1)), "1.0");
        assert_eq!(ms(Duration::from_nanos(4_200)), "0.0");
    }

    /// The kernel line names the component then the release — grep
    /// target first, value second, the order every trace line keeps.
    #[test]
    fn kernel_line_pins_the_shape() {
        assert_eq!(
            kernel_line("limiter", "6.8.0-45-generic"),
            "[limiter] kernel 6.8.0-45-generic"
        );
        assert_eq!(
            kernel_line("ebpf", "5.15.0-102-generic"),
            "[ebpf] kernel 5.15.0-102-generic"
        );
    }

    /// The load summary carries singular/plural units — "1 program,
    /// 1 map", never "1 programs".
    #[test]
    fn load_line_pins_counts_and_units() {
        assert_eq!(
            load_line("limiter", 2, 9, Duration::from_millis(8)),
            "[limiter] object loaded: 2 programs, 9 maps in 8.0ms"
        );
        assert_eq!(
            load_line("ebpf", 1, 1, Duration::from_micros(4_100)),
            "[ebpf] object loaded: 1 program, 1 map in 4.1ms"
        );
    }

    /// The map inventory line mirrors bpftool field vocabulary so a
    /// trace line cross-checks against `bpftool map show id <id>`.
    #[test]
    fn map_line_pins_the_inventory_shape() {
        assert_eq!(
            map_line("limiter", "cgroup_policy_dl", 123, "hash", 4, 16, 1024),
            "[limiter] map cgroup_policy_dl: id 123, hash map, key 4B, value 16B, max_entries 1024"
        );
        assert_eq!(
            map_line("ebpf", "schema_version", 9, "array", 4, 4, 1),
            "[ebpf] map schema_version: id 9, array map, key 4B, value 4B, max_entries 1"
        );
    }

    /// bpftool vocabulary for the map types zelynic objects define
    /// (hash + array), the near neighbors, and the unknown fallback.
    #[test]
    fn map_type_name_uses_bpftool_vocabulary() {
        assert_eq!(map_type_name(MapType::Hash), "hash");
        assert_eq!(map_type_name(MapType::Array), "array");
        assert_eq!(map_type_name(MapType::PerCpuHash), "percpu hash");
        assert_eq!(map_type_name(MapType::PerCpuArray), "percpu array");
        assert_eq!(map_type_name(MapType::LruHash), "lru hash");
        assert_eq!(map_type_name(MapType::StackTrace), "stack trace");
        assert_eq!(map_type_name(MapType::Unspecified), "other");
    }
}
