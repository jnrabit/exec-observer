//! Minimaler BTF-Parser zur Offset-Extraktion (manuelles CO-RE).
//!
//! Liest `/sys/kernel/btf/vmlinux` und liefert die Byte-Offsets von
//! Struct-Feldern. Kein externes Werkzeug; basiert auf dem BTF-Binärformat
//! (Header inkl. erweitertem 32-Byte-Header, Offsets relativ zum Header-Ende).
//!
//! Der Walker überspringt alle Typen, bis er den gesuchten Struct-Namen findet.
//! Wichtig (S1): Jede `vlen`-Familie muss exakt abgedeckt sein – ein
//! übersprungenes Kind (z. B. `UNION`) versetzt die Position und liefert auf
//! anderen Kerneln stillschweigend falsche Offsets.

use std::fs;

const BTF_MAGIC: u16 = 0xEB9F;

// BTF-Kind-Konstanten (Kurzopt 3): keine Magic Numbers im Walker.
const KIND_INT: u32 = 1;
const KIND_ARRAY: u32 = 3;
const KIND_STRUCT: u32 = 4;
const KIND_UNION: u32 = 5;
const KIND_ENUM: u32 = 6;
const KIND_FUNC_PROTO: u32 = 13;
const KIND_VAR: u32 = 14;
const KIND_DATASEC: u32 = 15;
const KIND_DECL_TAG: u32 = 17;
const KIND_ENUM64: u32 = 19;

/// Liest ein `u32` (little-endian) ab `off`, wenn ausreichend Bytes folgen.
#[inline]
fn read_u32(data: &[u8], off: usize) -> Option<u32> {
    Some(u32::from_le_bytes(data.get(off..off + 4)?.try_into().ok()?))
}

pub struct Btf {
    data: Vec<u8>,
    hdr_len: usize,
    type_off: usize,
    type_len: usize,
    str_off: usize,
    str_len: usize,
}

impl Btf {
    /// Liest die System-BTF aus `/sys/kernel/btf/vmlinux`.
    pub fn from_sysfs() -> Result<Self, String> {
        let data = fs::read("/sys/kernel/btf/vmlinux").map_err(|e| e.to_string())?;
        Self::parse(data)
    }

    pub fn parse(data: Vec<u8>) -> Result<Self, String> {
        let hdr = |off| read_u32(&data, off).ok_or_else(|| "BTF-Header unvollständig".to_string());
        let magic = hdr(0)? as u16;
        if magic != BTF_MAGIC {
            return Err(format!("falsche BTF-Magic: {magic:#x}"));
        }
        let hdr_len = hdr(4)? as usize;
        let type_off = hdr(8)? as usize;
        let type_len = hdr(12)? as usize;
        let str_off = hdr(16)? as usize;
        let str_len = hdr(20)? as usize;
        // Bounds-Prüfung statt Panik bei korrupten/absurden Offsets:
        // hdr_len + type_off + type_len ≤ len und hdr_len + str_off + str_len ≤ len.
        let types_end = hdr_len
            .checked_add(type_off)
            .and_then(|t| t.checked_add(type_len));
        let strs_end = hdr_len
            .checked_add(str_off)
            .and_then(|s| s.checked_add(str_len));
        if hdr_len < 24
            || hdr_len > data.len()
            || types_end.is_none_or(|t| t > data.len())
            || strs_end.is_none_or(|s| s > data.len())
        {
            return Err("ungültige BTF-Section-Offsets".to_string());
        }
        Ok(Self {
            data,
            hdr_len,
            type_off,
            type_len,
            str_off,
            str_len,
        })
    }

    fn string(&self, off: usize) -> String {
        let base = self.hdr_len + self.str_off;
        let end_base = (base + self.str_len).min(self.data.len());
        let Some(start) = base.checked_add(off) else {
            return String::new();
        };
        if start >= end_base {
            return String::new();
        }
        let mut end = start;
        while end < end_base && self.data[end] != 0 {
            end += 1;
        }
        String::from_utf8_lossy(&self.data[start..end]).into_owned()
    }

    /// Liefert den Byte-Offset des Feldes `field` im Struct `struct_name`,
    /// oder `None`, wenn Struct oder Feld nicht existiert.
    ///
    /// Anonyme Unter-Structs/Unions werden rekursiv durchsucht: Bei
    /// `__randomize_layout`-Kernen (z. B. `mm_struct` auf dem Zielkernel) ist
    /// der benannte Typ nur eine Hülle (`('', <anonym>)`, `flexible_array`);
    /// der echte Rumpf – hier mit `exe_file` – steckt im anonymen Member an
    /// Offset 0. Ohne Rekursion wäre `field_offset("mm_struct", "exe_file")`
    /// stillschweigend `None` und der Daemon startete nie (fail-closed statt
    /// falscher Offsets).
    pub fn field_offset(&self, struct_name: &str, field_name: &str) -> Option<usize> {
        let id = self.struct_id_by_name(struct_name)?;
        self.member_offset(id, field_name, 0)
    }

    /// Sucht die Typ-ID eines STRUCT/UNION per Namen (erster Treffer).
    fn struct_id_by_name(&self, struct_name: &str) -> Option<u32> {
        let start = self.hdr_len + self.type_off;
        let end = start + self.type_len;
        let types = &self.data[start..end];
        let mut i = 0usize;
        let mut id = 0u32;

        while i + 12 <= types.len() {
            let name_off = read_u32(types, i)? as usize;
            let info = read_u32(types, i + 4)?;
            let kind = (info >> 24) & 0x1f;
            let vlen = (info & 0xffff) as usize;
            i += 12;
            id += 1;

            if (kind == KIND_STRUCT || kind == KIND_UNION) && self.string(name_off) == struct_name {
                return Some(id);
            }
            i = Self::skip_members(types, i, kind, vlen)?;
        }
        None
    }

    /// Springt über die Nutzdaten eines Typ-Eintrags. `None` bei korrupten
    /// Längen oder unbekanntem Kind mit `vlen`-Nutzdaten (fail-closed statt
    /// Desynchronisation, siehe S1).
    fn skip_members(types: &[u8], i: usize, kind: u32, vlen: usize) -> Option<usize> {
        let step = match kind {
            KIND_STRUCT | KIND_UNION => vlen.checked_mul(12)?,
            KIND_INT => 4,
            KIND_ARRAY => 12,
            KIND_ENUM => vlen.checked_mul(8)?,
            KIND_FUNC_PROTO => vlen.checked_mul(8)?,
            KIND_VAR => 4,
            KIND_DATASEC => vlen.checked_mul(12)?,
            KIND_DECL_TAG => 4,
            KIND_ENUM64 => vlen.checked_mul(12)?,
            // PTR/TYPEDEF/CONST/VOLATILE/RESTRICT/FWD/FUNC/FLOAT/TYPE_TAG:
            // keine zusätzlichen Daten.
            _ => {
                if vlen != 0 {
                    return None;
                }
                0
            }
        };
        i.checked_add(step).filter(|&n| n <= types.len())
    }

    /// Liest den Kopf eines Typ-Eintrags per Typ-ID: (Kind, vlen, Byte-Offset
    /// der Member-Daten in der Typsection).
    fn type_header(&self, want: u32) -> Option<(u32, usize, usize)> {
        let start = self.hdr_len + self.type_off;
        let end = start + self.type_len;
        let types = &self.data[start..end];
        let mut i = 0usize;
        let mut id = 0u32;

        while i + 12 <= types.len() {
            let info = read_u32(types, i + 4)?;
            let kind = (info >> 24) & 0x1f;
            let vlen = (info & 0xffff) as usize;
            i += 12;
            id += 1;
            if id == want {
                return Some((kind, vlen, i));
            }
            i = Self::skip_members(types, i, kind, vlen)?;
        }
        None
    }

    /// Sucht `field_name` in STRUCT/UNION `type_id`. Anonyme Member, deren Typ
    /// selbst STRUCT/UNION ist, werden rekursiv durchsucht (Basis-Offset wird
    /// addiert). `depth` deckelt die Rekursion gegen korrupte BTF.
    fn member_offset(&self, type_id: u32, field_name: &str, depth: u8) -> Option<usize> {
        if depth > 8 {
            return None;
        }
        let start = self.hdr_len + self.type_off;
        let end = start + self.type_len;
        let types = &self.data[start..end];
        let (kind, vlen, mut i) = self.type_header(type_id)?;
        if kind != KIND_STRUCT && kind != KIND_UNION {
            return None;
        }
        for _ in 0..vlen {
            if i + 12 > types.len() {
                return None;
            }
            let mo = read_u32(types, i)? as usize;
            let mtype = read_u32(types, i + 4)?;
            let moff = read_u32(types, i + 8)?;
            i += 12;
            let name = self.string(mo);
            if name == field_name {
                // Offset ist in Bits (kind_flag für Bitfields
                // irrelevant: hier nur Nicht-Bitfield-Felder).
                return Some((moff & 0xffffff) as usize / 8);
            }
            // Anonymes Member eines Structs/Unions (Randstruct-Hülle):
            // darin weitersuchen, Basis-Offset addieren.
            if name.is_empty() {
                if let Some((mkind, _, _)) = self.type_header(mtype) {
                    if mkind == KIND_STRUCT || mkind == KIND_UNION {
                        if let Some(inner) = self.member_offset(mtype, field_name, depth + 1) {
                            return Some(((moff & 0xffffff) as usize / 8) + inner);
                        }
                    }
                }
            }
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_sysfs_and_finds_offsets() {
        let btf = match Btf::from_sysfs() {
            Ok(b) => b,
            // Als normaler Nutzer kann `/sys/kernel/btf/vmlinux` unlesbar
            // sein; der Daemon läuft als root und scheitert dort fail-closed.
            // Kein Fehlschlag des Host-Tests, sondern ein Skip mit Grund.
            Err(e) => {
                eprintln!("SKIP: /sys/kernel/btf/vmlinux nicht lesbar ({e})");
                return;
            }
        };
        let real_parent = btf.field_offset("task_struct", "real_parent");
        let tgid = btf.field_offset("task_struct", "tgid");
        let cred = btf.field_offset("task_struct", "cred");
        let uid = btf.field_offset("cred", "uid");
        let euid = btf.field_offset("cred", "euid");
        let start_time = btf.field_offset("task_struct", "start_time");
        let start_boottime = btf.field_offset("task_struct", "start_boottime");
        let group_leader = btf.field_offset("task_struct", "group_leader");
        // Ereignis-Identität (ino/size): mm -> exe_file -> f_inode.
        let mm = btf.field_offset("task_struct", "mm");
        let exe_file = btf.field_offset("mm_struct", "exe_file");
        let f_inode = btf.field_offset("file", "f_inode");
        let i_ino = btf.field_offset("inode", "i_ino");
        let i_size = btf.field_offset("inode", "i_size");

        assert!(real_parent.is_some(), "task_struct.real_parent fehlt");
        assert!(tgid.is_some(), "task_struct.tgid fehlt");
        assert!(cred.is_some(), "task_struct.cred fehlt");
        assert!(uid.is_some(), "cred.uid fehlt");
        assert!(euid.is_some(), "cred.euid fehlt");
        assert!(start_time.is_some(), "task_struct.start_time fehlt");
        assert!(start_boottime.is_some(), "task_struct.start_boottime fehlt");
        assert!(
            group_leader.is_some(),
            "task_struct.group_leader fehlt (ARGS-Identität)"
        );
        assert!(mm.is_some(), "task_struct.mm fehlt (Ereignis-Identität)");
        assert!(exe_file.is_some(), "mm_struct.exe_file fehlt");
        assert!(f_inode.is_some(), "file.f_inode fehlt");
        assert!(i_ino.is_some(), "inode.i_ino fehlt");
        assert!(i_size.is_some(), "inode.i_size fehlt");

        // Kernel-Layout von struct cred: uid, gid, suid, sgid, euid, egid,
        // fsuid, fsgid als 8 × u32 hintereinander.
        assert_eq!(
            euid,
            uid.map(|u| u + 16),
            "cred.euid sollte 16 Byte nach cred.uid liegen"
        );

        // Es gibt UNION-Typen in der Kernel-BTF – ohne den UNION-Branch wäre der
        // Walker unterwegs desynchronisiert gewesen (Regressionstest zu S1).
        assert!(
            btf_has_union(&btf),
            "vmlinux-BTF enthält keine UNION-Typen – Test deckt S1 nicht ab"
        );
    }

    /// Zählt UNION-Kinds in der BTF-Typsection (beweist, dass S1 wirksam ist).
    fn btf_has_union(btf: &Btf) -> bool {
        let start = btf.hdr_len + btf.type_off;
        let end = start + btf.type_len;
        let types = &btf.data[start..end];
        let mut i = 0usize;
        while i + 12 <= types.len() {
            let info = read_u32(types, i + 4).unwrap();
            let kind = (info >> 24) & 0x1f;
            let vlen = (info & 0xffff) as usize;
            i += 12;
            if kind == KIND_UNION {
                return true;
            }
            i += match kind {
                KIND_INT => 4,
                KIND_ARRAY => 12,
                KIND_STRUCT | KIND_UNION => vlen * 12,
                KIND_ENUM | KIND_FUNC_PROTO => vlen * 8,
                KIND_VAR | KIND_DECL_TAG => 4,
                KIND_DATASEC | KIND_ENUM64 => vlen * 12,
                _ => 0,
            };
        }
        false
    }

    /// Synthetisches BTF: INT → UNION (2 Member) → struct task_struct.
    /// Ohne den UNION-Branch läuft der Walker nach der Union in die Member-Daten
    /// und findet `task_struct` nicht (falsche Offsets). Mit Skip: Some(0).
    #[test]
    fn union_between_types_is_skipped() {
        // String-Tabelle: ["", "int_t", "union_x", "a", "b", "task_struct", "real_parent"]
        let strs: [&[u8]; 7] = [
            b"\0",
            b"int_t\0",
            b"union_x\0",
            b"a\0",
            b"b\0",
            b"task_struct\0",
            b"real_parent\0",
        ];
        let mut str_off = 0usize;
        let mut str_offsets = Vec::new();
        for s in strs {
            str_offsets.push(str_off);
            str_off += s.len();
        }

        let mut types = Vec::new();
        let mut u = |x: u32| types.extend_from_slice(&x.to_le_bytes());
        // INT (kind 1): 12-Byte-Header + 4-Byte int_data
        u(str_offsets[1] as u32);
        u(1 << 24); // kind=1
        u(4); // size
        u(32); // int_data (encoding=0, offset=0, bits=32)
               // UNION (kind 5, vlen=2): header + 2 × member à 12 Byte
        u(str_offsets[2] as u32);
        u((5 << 24) | 2);
        u(8); // size (union)
        u(str_offsets[3] as u32); // member a
        u(0);
        u(0);
        u(str_offsets[4] as u32); // member b
        u(0);
        u(32);
        // STRUCT task_struct (kind 4, vlen=1): header + member real_parent
        u(str_offsets[5] as u32);
        u((4 << 24) | 1);
        u(16); // size
        u(str_offsets[6] as u32); // member real_parent
        u(0);
        u(0); // bits_offset 0

        // BTF-Header (24 Byte): magic(u16)+version(u8)+flags(u8), danach 5×u32.
        let _type_off = 0usize; // Typsection direkt hinter dem Header
        let type_len = types.len();
        let str_len = strs.iter().map(|s| s.len()).sum::<usize>();
        let str_off = type_len; // Strings folgen direkt auf die Typen
        let mut data = Vec::new();
        data.extend_from_slice(&BTF_MAGIC.to_le_bytes());
        data.push(1); // version
        data.push(0); // flags
        data.extend_from_slice(&24u32.to_le_bytes()); // hdr_len
        data.extend_from_slice(&0u32.to_le_bytes()); // type_off
        data.extend_from_slice(&(type_len as u32).to_le_bytes());
        data.extend_from_slice(&(str_off as u32).to_le_bytes());
        data.extend_from_slice(&(str_len as u32).to_le_bytes());
        data.extend_from_slice(&types);
        for s in strs {
            data.extend_from_slice(s);
        }

        let btf = Btf::parse(data).expect("synthetisches BTF parse");
        assert_eq!(btf.field_offset("task_struct", "real_parent"), Some(0));
        assert_eq!(btf.field_offset("task_struct", "gibt_es_nicht"), None);
    }

    /// Synthetisches BTF für Randstruct-Hüllen: benannter STRUCT `mm_struct`
    /// mit anonymem Member (echter Rumpf mit `exe_file`) plus Rest-Member.
    /// Ohne Rekursion in anonyme Member wäre das Ergebnis `None`; mit
    /// Rekursion der innere Offset (hier Byte 8).
    #[test]
    fn anonymous_wrapper_member_is_searched_recursively() {
        // Strings: ["", "exe_file", "flexible_array", "mm_struct"]
        let strs: [&[u8]; 4] = [b"\0", b"exe_file\0", b"flexible_array\0", b"mm_struct\0"];
        let mut str_offsets = Vec::new();
        let mut str_off = 0usize;
        for s in strs {
            str_offsets.push(str_off);
            str_off += s.len();
        }

        let mut types = Vec::new();
        let mut u = |x: u32| types.extend_from_slice(&x.to_le_bytes());
        // Typ 1: anonymer STRUCT (kind 4, vlen=1), Member exe_file an Bit 64.
        u(0);
        u((4 << 24) | 1);
        u(16);
        u(str_offsets[1] as u32); // exe_file
        u(0);
        u(64);
        // Typ 2: STRUCT mm_struct (kind 4, vlen=2): anonymes Member (Typ 1)
        // an Bit 0, flexible_array an Bit 128.
        u(str_offsets[3] as u32); // mm_struct
        u((4 << 24) | 2);
        u(32);
        u(0); // anonymes Member
        u(1); // Typ 1
        u(0);
        u(str_offsets[2] as u32); // flexible_array
        u(0);
        u(128);

        let type_len = types.len();
        let str_len = strs.iter().map(|s| s.len()).sum::<usize>();
        let str_off = type_len;
        let mut data = Vec::new();
        data.extend_from_slice(&BTF_MAGIC.to_le_bytes());
        data.push(1);
        data.push(0);
        data.extend_from_slice(&24u32.to_le_bytes());
        data.extend_from_slice(&0u32.to_le_bytes());
        data.extend_from_slice(&(type_len as u32).to_le_bytes());
        data.extend_from_slice(&(str_off as u32).to_le_bytes());
        data.extend_from_slice(&(str_len as u32).to_le_bytes());
        data.extend_from_slice(&types);
        for s in strs {
            data.extend_from_slice(s);
        }

        let btf = Btf::parse(data).expect("synthetisches BTF parse");
        assert_eq!(btf.field_offset("mm_struct", "exe_file"), Some(8));
        assert_eq!(btf.field_offset("mm_struct", "gibt_es_nicht"), None);
    }

    #[test]
    fn unknown_kind_with_payload_is_rejected() {
        // Ein unbekanntes Kind VOR dem gesuchten Struct: der Walker darf die
        // unbekannte Nutzdatenlänge nicht raten und liefert deshalb None statt
        // eines möglicherweise falschen Offsets.
        let strs: [&[u8]; 3] = [b"\0", b"task_struct\0", b"real_parent\0"];
        let mut str_offsets = Vec::new();
        let mut str_off = 0usize;
        for s in strs {
            str_offsets.push(str_off);
            str_off += s.len();
        }

        let mut types = Vec::new();
        let mut u = |x: u32| types.extend_from_slice(&x.to_le_bytes());
        u(0); // Name
        u((25 << 24) | 1); // unbekanntes Kind mit vlen=1
        u(4); // Größe
        u(0xdead_beef); // unbekannte Nutzdaten
        u(str_offsets[1] as u32);
        u((4 << 24) | 1);
        u(16);
        u(str_offsets[2] as u32);
        u(0);
        u(0);

        let type_len = types.len();
        let str_len = strs.iter().map(|s| s.len()).sum::<usize>();
        let mut data = Vec::new();
        data.extend_from_slice(&BTF_MAGIC.to_le_bytes());
        data.push(1);
        data.push(0);
        data.extend_from_slice(&24u32.to_le_bytes());
        data.extend_from_slice(&0u32.to_le_bytes());
        data.extend_from_slice(&(type_len as u32).to_le_bytes());
        data.extend_from_slice(&(type_len as u32).to_le_bytes());
        data.extend_from_slice(&(str_len as u32).to_le_bytes());
        data.extend_from_slice(&types);
        for s in strs {
            data.extend_from_slice(s);
        }

        let btf = Btf::parse(data).expect("Header gültig");
        assert_eq!(btf.field_offset("task_struct", "real_parent"), None);
    }

    #[test]
    fn missing_field_returns_none() {
        let btf = match Btf::from_sysfs() {
            Ok(b) => b,
            Err(e) => {
                eprintln!("SKIP: /sys/kernel/btf/vmlinux nicht lesbar ({e})");
                return;
            }
        };
        assert_eq!(btf.field_offset("task_struct", "gibt_es_nicht_xyz"), None);
        assert_eq!(btf.field_offset("struct_gibt_es_nicht", "pid"), None);
    }

    /// Korrupte Section-Offsets dürfen nicht paniken, sondern führen zu `Err`.
    #[test]
    fn corrupt_offsets_no_panic() {
        for (type_len, str_len) in [(0xffff_ffffu32, 16u32), (16, 0xffff_ff00), (0x7fff_fffe, 1)] {
            let mut data = Vec::new();
            data.extend_from_slice(&BTF_MAGIC.to_le_bytes());
            data.push(1);
            data.push(0);
            data.extend_from_slice(&24u32.to_le_bytes()); // hdr_len
            data.extend_from_slice(&0u32.to_le_bytes()); // type_off
            data.extend_from_slice(&type_len.to_le_bytes());
            data.extend_from_slice(&16u32.to_le_bytes()); // str_off
            data.extend_from_slice(&str_len.to_le_bytes());
            assert!(
                Btf::parse(data).is_err(),
                "corrupt {type_len:#x}/{str_len:#x}"
            );
        }
    }

    /// Absurde String-Offsets liefern einen leeren String statt einer Panik.
    #[test]
    fn absurd_string_offset_no_panic() {
        let data = {
            let mut d = Vec::new();
            d.extend_from_slice(&BTF_MAGIC.to_le_bytes());
            d.push(1);
            d.push(0);
            d.extend_from_slice(&24u32.to_le_bytes());
            d.extend_from_slice(&0u32.to_le_bytes());
            d.extend_from_slice(&0u32.to_le_bytes()); // type_len
            d.extend_from_slice(&0u32.to_le_bytes()); // str_off
            d.extend_from_slice(&4u32.to_le_bytes()); // str_len
            d.extend_from_slice(b"\0abc");
            d
        };
        let btf = Btf::parse(data).expect("gültiger Minimal-Header");
        assert_eq!(btf.field_offset("gibt_es_nicht", "x"), None);
        assert_eq!(btf.string(usize::MAX), "");
    }
}
