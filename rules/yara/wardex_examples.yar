// Wardex example rules demonstrating the supported .yar subset.
// See docs/YARA_COMPATIBILITY.md for exactly what is implemented.
//
// These are original, Wardex-authored examples for demonstration and
// testing — not vendored from any third-party ruleset.

rule Suspicious_Base64_PowerShell_Cradle : downloader suspicious
{
    meta:
        author = "Wardex"
        description = "PowerShell invoked with an encoded command, a common download-cradle pattern"
        severity = "High"
        mitre_ids = "T1059.001,T1027"
    strings:
        $ps = "powershell" nocase
        $flag = "-EncodedCommand" nocase
        $b64 = /[A-Za-z0-9+\/]{40,}={0,2}/
    condition:
        $ps and $flag and $b64
}

rule Tiny_ELF_UPX_Packed : packer
{
    meta:
        author = "Wardex"
        description = "ELF binary carrying a UPX signature near the start of the file"
        severity = "Medium"
    strings:
        $elf_magic = { 7F 45 4C 46 }
        $upx_sig = "UPX!"
    condition:
        $elf_magic at 0 and $upx_sig and filesize < 50MB
}

private rule Has_MZ_Header
{
    strings:
        $mz = { 4D 5A }
    condition:
        $mz at 0
}

rule Windows_PE_With_Suspicious_Section_Count : pe
{
    meta:
        author = "Wardex"
        description = "PE file whose DOS header is present alongside several loader-evasion string indicators"
        severity = "Medium"
    strings:
        $s1 = "VirtualAlloc" nocase
        $s2 = "VirtualProtect" nocase
        $s3 = "CreateRemoteThread" nocase
        $s4 = "LoadLibraryA" nocase
    condition:
        Has_MZ_Header and 2 of ($s*)
}
