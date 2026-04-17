//! File entropy analysis for detecting packed, encrypted, or polymorphic malware.
//!
//! Calculates Shannon entropy over byte windows and performs section-level
//! analysis on PE/ELF binaries to detect packing signatures.

use serde::{Deserialize, Serialize};

// ── Types ────────────────────────────────────────────────────────────────────

/// Entropy analysis of a single binary section or region.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SectionEntropy {
    pub name: String,
    pub offset: usize,
    pub size: usize,
    pub entropy: f64,
    pub suspicious: bool,
}

/// Complete entropy report for a file/buffer.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EntropyReport {
    pub overall_entropy: f64,
    pub sections: Vec<SectionEntropy>,
    pub is_packed: bool,
    pub packer_hint: Option<String>,
    pub suspicious: bool,
    pub high_entropy_ratio: f64,
    pub file_size: usize,
}

/// Known packer signatures (magic bytes at specific offsets).
struct PackerSignature {
    name: &'static str,
    pattern: &'static [u8],
    offset_range: (usize, usize),
}

const PACKER_SIGNATURES: &[PackerSignature] = &[
    PackerSignature {
        name: "UPX",
        pattern: b"UPX!",
        offset_range: (0, 1024),
    },
    PackerSignature {
        name: "UPX",
        pattern: b"UPX0",
        offset_range: (0, 2048),
    },
    PackerSignature {
        name: "UPX",
        pattern: b"UPX1",
        offset_range: (0, 2048),
    },
    PackerSignature {
        name: "Themida/WinLicense",
        pattern: b".themida",
        offset_range: (0, 4096),
    },
    PackerSignature {
        name: "ASPack",
        pattern: b".aspack",
        offset_range: (0, 4096),
    },
    PackerSignature {
        name: "PECompact",
        pattern: b"PEC2",
        offset_range: (0, 2048),
    },
    PackerSignature {
        name: "MPRESS",
        pattern: b".MPRESS1",
        offset_range: (0, 4096),
    },
    PackerSignature {
        name: "VMProtect",
        pattern: b".vmp0",
        offset_range: (0, 4096),
    },
    PackerSignature {
        name: "VMProtect",
        pattern: b".vmp1",
        offset_range: (0, 4096),
    },
    PackerSignature {
        name: "Enigma Protector",
        pattern: b".enigma1",
        offset_range: (0, 4096),
    },
    PackerSignature {
        name: "NSPack",
        pattern: b".nsp0",
        offset_range: (0, 4096),
    },
    PackerSignature {
        name: "PEtite",
        pattern: b".petite",
        offset_range: (0, 4096),
    },
];

// ── Entropy Calculation ──────────────────────────────────────────────────────

/// Calculate Shannon entropy for a byte slice (0.0 = uniform, 8.0 = maximum randomness).
pub fn shannon_entropy(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }
    let mut freq = [0u64; 256];
    for &b in data {
        freq[b as usize] += 1;
    }
    let len = data.len() as f64;
    let mut entropy = 0.0;
    for &count in &freq {
        if count > 0 {
            let p = count as f64 / len;
            entropy -= p * p.log2();
        }
    }
    entropy
}

/// Calculate entropy over sliding windows, returning per-window entropy values.
pub fn windowed_entropy(data: &[u8], window_size: usize) -> Vec<f64> {
    if data.len() < window_size || window_size == 0 {
        return vec![shannon_entropy(data)];
    }
    let step = window_size / 2; // 50% overlap
    let mut results = Vec::new();
    let mut offset = 0;
    while offset + window_size <= data.len() {
        results.push(shannon_entropy(&data[offset..offset + window_size]));
        offset += step;
    }
    results
}

// ── Packer Detection ─────────────────────────────────────────────────────────

/// Check for known packer signatures in the binary.
fn detect_packer(data: &[u8]) -> Option<String> {
    for sig in PACKER_SIGNATURES {
        let end = sig.offset_range.1.min(data.len());
        if end < sig.pattern.len() {
            continue;
        }
        let search_range = &data[sig.offset_range.0..end];
        if search_range
            .windows(sig.pattern.len())
            .any(|w| w == sig.pattern)
        {
            return Some(sig.name.to_string());
        }
    }
    None
}

// ── PE/ELF Section Analysis ──────────────────────────────────────────────────

/// Minimal PE section header extraction.
fn parse_pe_sections(data: &[u8]) -> Vec<SectionEntropy> {
    let mut sections = Vec::new();

    // Check MZ header
    if data.len() < 64 || data[0] != b'M' || data[1] != b'Z' {
        return sections;
    }

    // e_lfanew at offset 0x3C
    let pe_offset = u32::from_le_bytes([data[0x3C], data[0x3D], data[0x3E], data[0x3F]]) as usize;
    if pe_offset + 24 > data.len() {
        return sections;
    }

    // Check PE\0\0
    if &data[pe_offset..pe_offset + 4] != b"PE\0\0" {
        return sections;
    }

    let num_sections = u16::from_le_bytes([data[pe_offset + 6], data[pe_offset + 7]]) as usize;
    let opt_hdr_size = u16::from_le_bytes([data[pe_offset + 20], data[pe_offset + 21]]) as usize;

    let section_table_offset = pe_offset + 24 + opt_hdr_size;

    for i in 0..num_sections.min(64) {
        let off = section_table_offset + i * 40;
        if off + 40 > data.len() {
            break;
        }

        let name_bytes = &data[off..off + 8];
        let name = std::str::from_utf8(name_bytes)
            .unwrap_or("???")
            .trim_end_matches('\0')
            .to_string();

        let raw_size = u32::from_le_bytes([
            data[off + 16],
            data[off + 17],
            data[off + 18],
            data[off + 19],
        ]) as usize;
        let raw_offset = u32::from_le_bytes([
            data[off + 20],
            data[off + 21],
            data[off + 22],
            data[off + 23],
        ]) as usize;

        if raw_offset + raw_size > data.len() || raw_size == 0 {
            continue;
        }

        let entropy = shannon_entropy(&data[raw_offset..raw_offset + raw_size]);
        let suspicious = entropy > 7.0 || (name == ".text" && entropy > 6.8);

        sections.push(SectionEntropy {
            name,
            offset: raw_offset,
            size: raw_size,
            entropy,
            suspicious,
        });
    }

    sections
}

/// Minimal ELF section header extraction.
fn parse_elf_sections(data: &[u8]) -> Vec<SectionEntropy> {
    let mut sections = Vec::new();

    // ELF magic: 0x7F 'E' 'L' 'F'
    if data.len() < 64 || &data[0..4] != b"\x7fELF" {
        return sections;
    }

    let is_64 = data[4] == 2;

    let (sh_offset, sh_entsize, sh_num, sh_strndx) = if is_64 {
        if data.len() < 64 {
            return sections;
        }
        let off = u64::from_le_bytes(data[40..48].try_into().unwrap_or_default()) as usize;
        let entsz = u16::from_le_bytes([data[58], data[59]]) as usize;
        let num = u16::from_le_bytes([data[60], data[61]]) as usize;
        let strndx = u16::from_le_bytes([data[62], data[63]]) as usize;
        (off, entsz, num, strndx)
    } else {
        if data.len() < 52 {
            return sections;
        }
        let off = u32::from_le_bytes(data[32..36].try_into().unwrap_or_default()) as usize;
        let entsz = u16::from_le_bytes([data[46], data[47]]) as usize;
        let num = u16::from_le_bytes([data[48], data[49]]) as usize;
        let strndx = u16::from_le_bytes([data[50], data[51]]) as usize;
        (off, entsz, num, strndx)
    };

    if sh_entsize == 0 || sh_num == 0 || sh_offset + sh_num * sh_entsize > data.len() {
        return sections;
    }

    // Get string table
    let strtab_hdr_off = sh_offset + sh_strndx * sh_entsize;
    if strtab_hdr_off + sh_entsize > data.len() {
        return sections;
    }

    let (strtab_off, strtab_size) = if is_64 {
        let o = u64::from_le_bytes(
            data[strtab_hdr_off + 24..strtab_hdr_off + 32]
                .try_into()
                .unwrap_or_default(),
        ) as usize;
        let s = u64::from_le_bytes(
            data[strtab_hdr_off + 32..strtab_hdr_off + 40]
                .try_into()
                .unwrap_or_default(),
        ) as usize;
        (o, s)
    } else {
        let o = u32::from_le_bytes(
            data[strtab_hdr_off + 16..strtab_hdr_off + 20]
                .try_into()
                .unwrap_or_default(),
        ) as usize;
        let s = u32::from_le_bytes(
            data[strtab_hdr_off + 20..strtab_hdr_off + 24]
                .try_into()
                .unwrap_or_default(),
        ) as usize;
        (o, s)
    };

    for i in 0..sh_num.min(128) {
        let hoff = sh_offset + i * sh_entsize;
        if hoff + sh_entsize > data.len() {
            break;
        }

        let (sec_offset, sec_size, name_idx) = if is_64 {
            let nidx =
                u32::from_le_bytes(data[hoff..hoff + 4].try_into().unwrap_or_default()) as usize;
            let o = u64::from_le_bytes(data[hoff + 24..hoff + 32].try_into().unwrap_or_default())
                as usize;
            let s = u64::from_le_bytes(data[hoff + 32..hoff + 40].try_into().unwrap_or_default())
                as usize;
            (o, s, nidx)
        } else {
            let nidx =
                u32::from_le_bytes(data[hoff..hoff + 4].try_into().unwrap_or_default()) as usize;
            let o = u32::from_le_bytes(data[hoff + 16..hoff + 20].try_into().unwrap_or_default())
                as usize;
            let s = u32::from_le_bytes(data[hoff + 20..hoff + 24].try_into().unwrap_or_default())
                as usize;
            (o, s, nidx)
        };

        if sec_size == 0 || sec_offset + sec_size > data.len() {
            continue;
        }

        let name = if name_idx < strtab_size && strtab_off + name_idx < data.len() {
            let start = strtab_off + name_idx;
            let end = data[start..]
                .iter()
                .position(|&b| b == 0)
                .map(|p| start + p)
                .unwrap_or(start + 32.min(data.len() - start));
            std::str::from_utf8(&data[start..end])
                .unwrap_or("???")
                .to_string()
        } else {
            format!("section_{i}")
        };

        let entropy = shannon_entropy(&data[sec_offset..sec_offset + sec_size]);
        let suspicious = entropy > 7.0 || (name == ".text" && entropy > 6.8);

        sections.push(SectionEntropy {
            name,
            offset: sec_offset,
            size: sec_size,
            entropy,
            suspicious,
        });
    }

    sections
}

// ── Public API ───────────────────────────────────────────────────────────────

/// Analyze a file buffer for entropy indicators of packing or encryption.
pub fn analyze_entropy(data: &[u8]) -> EntropyReport {
    let overall_entropy = shannon_entropy(data);

    // Try PE sections first, then ELF
    let mut sections = parse_pe_sections(data);
    if sections.is_empty() {
        sections = parse_elf_sections(data);
    }

    // If no sections parsed, create windows-based pseudo-sections
    if sections.is_empty() && data.len() > 256 {
        let window = 4096.min(data.len());
        let step = window;
        let mut offset = 0;
        let mut idx = 0;
        while offset + window <= data.len() {
            let entropy = shannon_entropy(&data[offset..offset + window]);
            sections.push(SectionEntropy {
                name: format!("block_{idx}"),
                offset,
                size: window,
                entropy,
                suspicious: entropy > 7.2,
            });
            offset += step;
            idx += 1;
        }
    }

    let packer_hint = detect_packer(data);

    let high_entropy_bytes: usize = sections
        .iter()
        .filter(|s| s.entropy > 7.0)
        .map(|s| s.size)
        .sum();
    let total_section_bytes: usize = sections.iter().map(|s| s.size).sum();
    let high_entropy_ratio = if total_section_bytes > 0 {
        high_entropy_bytes as f64 / total_section_bytes as f64
    } else {
        if overall_entropy > 7.0 { 1.0 } else { 0.0 }
    };

    let is_packed = packer_hint.is_some()
        || (overall_entropy > 7.2 && data.len() > 1024)
        || high_entropy_ratio > 0.75;

    let suspicious = is_packed || overall_entropy > 6.8 || sections.iter().any(|s| s.suspicious);

    EntropyReport {
        overall_entropy,
        sections,
        is_packed,
        packer_hint,
        suspicious,
        high_entropy_ratio,
        file_size: data.len(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn low_entropy_uniform_data() {
        let data = vec![0u8; 1024];
        let report = analyze_entropy(&data);
        assert!(report.overall_entropy < 0.1);
        assert!(!report.is_packed);
        assert!(!report.suspicious);
    }

    #[test]
    fn high_entropy_random_data() {
        // Simulate high-entropy (pseudo-random) data
        let data: Vec<u8> = (0..4096).map(|i| ((i * 17 + 31) % 256) as u8).collect();
        let report = analyze_entropy(&data);
        assert!(report.overall_entropy > 5.0);
    }

    #[test]
    fn upx_packed_detection() {
        let mut data = vec![0u8; 2048];
        data[100..104].copy_from_slice(b"UPX!");
        let report = analyze_entropy(&data);
        assert!(report.packer_hint.as_deref() == Some("UPX"));
        assert!(report.is_packed);
    }

    #[test]
    fn empty_data_safe() {
        let report = analyze_entropy(&[]);
        assert!(!report.is_packed);
        assert!(!report.suspicious);
        assert_eq!(report.overall_entropy, 0.0);
    }

    #[test]
    fn shannon_entropy_known_values() {
        // All same byte → 0 entropy
        assert_eq!(shannon_entropy(&[42; 100]), 0.0);
        // Two equally distributed bytes → 1.0 entropy
        let two_vals: Vec<u8> = (0..100).map(|i| if i % 2 == 0 { 0 } else { 1 }).collect();
        assert!((shannon_entropy(&two_vals) - 1.0).abs() < 0.01);
    }
}
