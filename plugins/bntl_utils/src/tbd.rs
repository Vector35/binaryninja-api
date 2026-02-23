//! Parse Apples TBD file format, which gives information about where source symbols are located.

use binaryninja::architecture::CoreArchitecture;
use binaryninja::platform::Platform;
use binaryninja::rc::Ref;
use serde::{Deserialize, Deserializer, Serialize};
use std::io::Read;
use std::str::FromStr;

pub fn parse_tbd_info(data: &mut impl Read) -> Result<Vec<TbdInfo>, serde_saphyr::Error> {
    let mut documents = Vec::new();
    for file in serde_saphyr::read::<_, TbdFile>(data) {
        // TODO: Float errors to caller
        if let Ok(info) = TbdInfo::try_from(file?) {
            documents.push(info);
        }
    }
    Ok(documents)
}

#[derive(Debug)]
pub struct TbdInfo {
    /// The installation name of the library.
    ///
    /// Ex. `/usr/lib/libSystem.B.dylib`
    pub install_name: String,
    pub targets: Vec<TbdTarget>,
    pub exports: Vec<ExportInfo>,
    pub current_version: Option<String>,
    pub compatibility_version: Option<String>,
}

#[derive(Debug)]
pub struct ExportInfo {
    pub targets: Vec<TbdTarget>,
    pub symbols: Vec<String>,
    pub objc_classes: Vec<String>,
}

#[derive(Debug, Serialize)]
pub enum TbdFile {
    #[serde(rename = "!tapi-tbd")]
    V4(TbdV4),
    #[serde(rename = "!tapi-tbd-v3")]
    V3(TbdLegacy),
    #[serde(rename = "!tapi-tbd-v2")]
    V2(TbdLegacy),
    #[serde(untagged)]
    V1(TbdLegacy),
}

impl<'de> Deserialize<'de> for TbdFile {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        use serde::de::Error;

        let value: serde_json::Value = Deserialize::deserialize(deserializer)?;
        // V4 requires the 'tbd-version' field, if we don't see that, then fallback to legacy.
        // TODO: If v5 comes out we will need to actually read the version field.
        if value.get("tbd-version").is_some() {
            let v4 = TbdV4::deserialize(value).map_err(D::Error::custom)?;
            Ok(TbdFile::V4(v4))
        } else if value.get("archs").is_some() && value.get("platform").is_some() {
            // TODO: It would be nice to determine v2 and v3 versions, but they are backwards compatible
            // TODO: so its not a higher priority (we do not differentiate between them anyways)
            let legacy = TbdLegacy::deserialize(value).map_err(D::Error::custom)?;
            Ok(TbdFile::V1(legacy))
        } else {
            Err(D::Error::custom(
                "Could not determine TBD version from tags or fields",
            ))
        }
    }
}

impl TryFrom<TbdFile> for TbdInfo {
    type Error = String;

    fn try_from(file: TbdFile) -> Result<Self, Self::Error> {
        match file {
            TbdFile::V4(v4) => TbdInfo::try_from(v4),
            TbdFile::V3(legacy) => TbdInfo::try_from(legacy),
            TbdFile::V2(legacy) => TbdInfo::try_from(legacy),
            TbdFile::V1(legacy) => TbdInfo::try_from(legacy),
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct TbdV4 {
    pub tbd_version: u32,
    pub targets: Vec<TbdTarget>,
    pub install_name: String,
    #[serde(default, deserialize_with = "coerce_string_opt")]
    pub current_version: Option<String>,
    #[serde(default, deserialize_with = "coerce_string_opt")]
    pub compatibility_version: Option<String>,
    #[serde(default)]
    pub swift_abi_version: Option<u32>,
    #[serde(default)]
    pub flags: Vec<String>,
    #[serde(default)]
    pub exports: Vec<ExportSectionV4>,
}

impl TryFrom<TbdV4> for TbdInfo {
    type Error = String;

    fn try_from(v4: TbdV4) -> Result<Self, Self::Error> {
        Ok(TbdInfo {
            install_name: v4.install_name,
            targets: v4.targets,
            exports: v4
                .exports
                .into_iter()
                .map(|e| ExportInfo {
                    targets: e.targets,
                    symbols: e.symbols,
                    objc_classes: e.objc_classes,
                })
                .collect(),
            current_version: v4.current_version,
            compatibility_version: v4.compatibility_version,
        })
    }
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct ExportSectionV4 {
    pub targets: Vec<TbdTarget>,
    #[serde(default)]
    pub symbols: Vec<String>,
    #[serde(default)]
    pub objc_classes: Vec<String>,
    #[serde(default)]
    pub objc_eh_types: Vec<String>,
    #[serde(default)]
    pub objc_ivars: Vec<String>,
}

/// Used for TBD files from older versions (1-3) of Xcode.
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct TbdLegacy {
    pub archs: Vec<TbdArchitecture>,
    pub platform: TbdPlatform,
    pub install_name: String,
    #[serde(default, deserialize_with = "coerce_string_opt")]
    pub current_version: Option<String>,
    // V1/V2 used swift-version [cite: 57, 63]
    #[serde(alias = "swift-version")]
    pub swift_abi_version: Option<String>,
    #[serde(default)]
    pub exports: Vec<ExportSectionLegacy>,
}

impl TryFrom<TbdLegacy> for TbdInfo {
    type Error = String;

    fn try_from(legacy: TbdLegacy) -> Result<Self, Self::Error> {
        let mut unified_exports = Vec::new();
        for export in legacy.exports {
            unified_exports.push(ExportInfo {
                targets: TbdTarget::from_seperate(&export.archs, &legacy.platform)?,
                symbols: export.symbols,
                objc_classes: export.objc_classes,
            });
        }

        Ok(TbdInfo {
            install_name: legacy.install_name,
            targets: TbdTarget::from_seperate(&legacy.archs, &legacy.platform)?,
            exports: unified_exports,
            current_version: legacy.current_version,
            compatibility_version: None,
        })
    }
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct ExportSectionLegacy {
    pub archs: Vec<TbdArchitecture>,
    #[serde(default)]
    pub symbols: Vec<String>,
    // V1 compatibility [cite: 57, 93]
    #[serde(alias = "allowed-clients")]
    pub allowable_clients: Option<Vec<String>>,
    #[serde(default)]
    pub objc_classes: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Hash)]
#[serde(rename_all = "lowercase")]
pub enum TbdArchitecture {
    I386,
    X86_64,
    X86_64h,
    Armv7,
    Armv7s,
    Armv7k,
    Arm64,
    Arm64e,
}

impl TbdArchitecture {
    pub fn binary_ninja_architecture(&self) -> Option<CoreArchitecture> {
        match self {
            TbdArchitecture::I386 => CoreArchitecture::by_name("x86"),
            TbdArchitecture::X86_64 => CoreArchitecture::by_name("x86_64"),
            TbdArchitecture::X86_64h => CoreArchitecture::by_name("x86_64"),
            TbdArchitecture::Armv7 => CoreArchitecture::by_name("armv7"),
            TbdArchitecture::Armv7s => CoreArchitecture::by_name("armv7"),
            TbdArchitecture::Armv7k => CoreArchitecture::by_name("armv7"),
            TbdArchitecture::Arm64 => CoreArchitecture::by_name("aarch64"),
            TbdArchitecture::Arm64e => CoreArchitecture::by_name("aarch64"),
        }
    }
}

impl FromStr for TbdArchitecture {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "i386" => Ok(TbdArchitecture::I386),
            "x86_64" => Ok(TbdArchitecture::X86_64),
            "x86_64h" => Ok(TbdArchitecture::X86_64h),
            "armv7" => Ok(TbdArchitecture::Armv7),
            "armv7s" => Ok(TbdArchitecture::Armv7s),
            "armv7k" => Ok(TbdArchitecture::Armv7k),
            "arm64" => Ok(TbdArchitecture::Arm64),
            "arm64e" => Ok(TbdArchitecture::Arm64e),
            _ => Err(format!("Unknown architecture: {}", s)),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Hash)]
#[serde(rename_all = "lowercase")]
pub enum TbdPlatform {
    Macos,
    Ios,
    IosSimulator,
    Tvos,
    TvosSimulator,
    Watchos,
    WatchosSimulator,
    Bridgeos,
    Maccatalyst,
}

impl TbdPlatform {
    pub fn binary_ninja_platform_str(&self) -> &'static str {
        match self {
            TbdPlatform::Macos => "mac",
            TbdPlatform::Ios => "ios",
            TbdPlatform::IosSimulator => "ios",
            TbdPlatform::Tvos => "tvos",
            TbdPlatform::TvosSimulator => "tvos",
            TbdPlatform::Watchos => "watchos",
            TbdPlatform::WatchosSimulator => "watchos",
            TbdPlatform::Bridgeos => "bridgeos",
            TbdPlatform::Maccatalyst => "mac",
        }
    }
}

impl FromStr for TbdPlatform {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "macos" | "macosx" => Ok(TbdPlatform::Macos),
            "ios" => Ok(TbdPlatform::Ios),
            "ios-simulator" => Ok(TbdPlatform::IosSimulator),
            "tvos" => Ok(TbdPlatform::Tvos),
            "tvos-simulator" => Ok(TbdPlatform::TvosSimulator),
            "watchos" => Ok(TbdPlatform::Watchos),
            "watchos-simulator" => Ok(TbdPlatform::WatchosSimulator),
            "bridgeos" => Ok(TbdPlatform::Bridgeos),
            "maccatalyst" => Ok(TbdPlatform::Maccatalyst),
            _ => Err(format!("Unknown platform: {}", s)),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Hash)]
pub struct TbdTarget {
    pub arch: TbdArchitecture,
    pub platform: TbdPlatform,
}

impl TbdTarget {
    pub fn from_seperate(
        archs: &[TbdArchitecture],
        platform: &TbdPlatform,
    ) -> Result<Vec<Self>, String> {
        archs
            .iter()
            .map(|a| {
                Ok(TbdTarget {
                    arch: *a,
                    platform: *platform,
                })
            })
            .collect()
    }

    pub fn binary_ninja_platform(&self) -> Option<Ref<Platform>> {
        let arch = self.arch.binary_ninja_architecture()?;
        let platform_str = self.platform.binary_ninja_platform_str();
        let arch_platform_str = format!("{}-{}", platform_str, arch.name());
        Platform::by_name(&arch_platform_str)
    }
}

impl FromStr for TbdTarget {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let parts: Vec<&str> = s.split('-').collect();
        if parts.len() < 2 {
            return Err(format!("Invalid target format: {}", s));
        }
        // The first part is always the architecture
        let arch = TbdArchitecture::from_str(parts[0])?;
        // The remaining parts form the platform [cite: 13, 15]
        let platform_str = parts[1..].join("-");
        let platform = TbdPlatform::from_str(&platform_str)?;
        Ok(TbdTarget { arch, platform })
    }
}

impl<'de> Deserialize<'de> for TbdTarget {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        TbdTarget::from_str(&s).map_err(serde::de::Error::custom)
    }
}

fn coerce_string_opt<'de, D>(deserializer: D) -> Result<Option<String>, D::Error>
where
    D: Deserializer<'de>,
{
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum RawValue {
        String(String),
        Float(f64),
        Int(i64),
    }

    match Option::<RawValue>::deserialize(deserializer)? {
        Some(RawValue::String(s)) => Ok(Some(s)),
        Some(RawValue::Float(f)) => Ok(Some(f.to_string())),
        Some(RawValue::Int(i)) => Ok(Some(i.to_string())),
        None => Ok(None),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    const LEGACY_TBD: &str = r#"
---
archs:           [ armv7, armv7s, arm64 ]
platform:        ios
install-name:    /usr/lib/libsqlite3.dylib
current-version: 216.4
compatibility-version: 9.0
exports:
  - archs:           [ armv7, armv7s, arm64 ]
    symbols:         [ _sqlite3VersionNumber, _sqlite3VersionString, _sqlite3_close ]
...
"#;

    const V4_TBD: &str = r#"
--- !tapi-tbd
tbd-version:     4
targets:         [ x86_64-macos, arm64-macos ]
install-name:    '/System/Library/Frameworks/VideoToolbox.framework/Versions/A/VideoToolbox'
current-version: 1.0
exports:
  - targets:         [ x86_64-macos, arm64-macos ]
    symbols:         [ _VTCompressionSessionCreate, _VTDecompressionSessionCreate ]
...
"#;

    #[test]
    fn test_parse_legacy_tbd() {
        let mut cursor = Cursor::new(LEGACY_TBD);
        let result = parse_tbd_info(&mut cursor).expect("Should parse legacy TBD");
        assert_eq!(result.len(), 1);
        let info = &result[0];
        assert_eq!(info.install_name, "/usr/lib/libsqlite3.dylib");
        assert_eq!(info.targets.len(), 3);
        assert_eq!(info.targets[0].arch, TbdArchitecture::Armv7);
        assert_eq!(info.targets[0].platform, TbdPlatform::Ios);
        let export = &info.exports[0];
        assert!(export.symbols.contains(&"_sqlite3_close".to_string()));
    }

    #[test]
    fn test_parse_v4_tbd() {
        let mut cursor = Cursor::new(V4_TBD);
        let result = parse_tbd_info(&mut cursor).expect("Should parse V4 TBD");

        assert_eq!(result.len(), 1);
        let info = &result[0];
        assert_eq!(
            info.install_name,
            "/System/Library/Frameworks/VideoToolbox.framework/Versions/A/VideoToolbox"
        );

        assert_eq!(info.targets.len(), 2);
        let has_arm64_macos = info
            .targets
            .iter()
            .any(|t| t.arch == TbdArchitecture::Arm64 && t.platform == TbdPlatform::Macos);
        assert!(has_arm64_macos);
    }

    #[test]
    fn test_multi_document_parsing() {
        // TBD v3+ supports multiple YAML documents in one file
        let multi_doc = format!("{}\n{}", V4_TBD, LEGACY_TBD);
        let mut cursor = Cursor::new(multi_doc);
        let result = parse_tbd_info(&mut cursor).expect("Should parse multiple documents");
        assert_eq!(result.len(), 2);
        assert_eq!(
            result[0].install_name,
            "/System/Library/Frameworks/VideoToolbox.framework/Versions/A/VideoToolbox"
        );
        assert_eq!(result[1].install_name, "/usr/lib/libsqlite3.dylib");
    }
}
