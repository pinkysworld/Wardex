# YARA compatibility

Wardex includes a built-in, pure-Rust rule engine (`src/yara_engine.rs`)
compatible with a well-defined *subset* of real YARA syntax, compiled by
`src/yara_parser.rs`. It does not embed or link the native `libyara` C
library, and it does not implement all of YARA — this document is the
precise boundary of what is supported, so a rule that compiles is a rule
that will actually be evaluated as written, and anything unsupported fails
loudly at load time instead of silently matching (or failing to match)
something else.

Rules can be authored two ways, loaded side by side:

- **`.yar` source** — the format described below, compiled by
  `yara_parser::compile`. Directory loading (`YaraEngine::load_rules_dir`)
  picks up every `*.yar`/`*.yara` file in `rules/yara/`.
- **JSON** — Wardex's original rule format (`YaraEngine::load_rules_json`),
  kept for backward compatibility with existing rule files and API-created
  rules. Both formats compile into the same internal `YaraRule` type and
  are scanned together.

## Rule structure

```
import "pe"                 // recognised and ignored, with a warning

private rule Helper          // `private`: excluded from scan results, but
{                             // usable from other rules' conditions
    strings:
        $a = "marker"
    condition:
        $a
}

rule MyRule : tag1 tag2      // tags are parsed and carried on the rule
{
    meta:
        author = "you"
        description = "..."
        severity = "High"
        mitre_ids = "T1059.001,T1027"   // comma-separated
        custom_key = 123                 // arbitrary meta lands in `meta.extra`

    strings:
        $a = "text" nocase wide ascii fullword
        $b = { 4D 5A ?? ?? [4-6] ( AA BB | CC ) }
        $c = /regex.../is

    condition:
        Helper and ($a or $b) and not $c
}
```

### Imports

`import "pe"`, `"elf"`, `"math"`, `"hash"`, `"time"`, and `"string"` are
accepted and ignored with a compile *warning* — no module fields
(`pe.imphash()`, etc.) are implemented, so a condition that actually
references one will fail to parse as an identifier/function call. Any
other module name is a hard **compile error**: Wardex refuses to guess at
what an unrecognised module's semantics should be.

### Rule modifiers

- `private rule` — evaluated (so other rules can reference it by name) but
  excluded from `ScanReport.results`.
- `global rule` — parsed and recorded (`YaraRule::is_global`), but Wardex
  does **not** implement YARA's "ANDed into every other rule" global-rule
  semantics. A global rule behaves like an ordinary rule; reference it
  explicitly from another rule's condition if you need that effect.

### Comments

`//` line comments and `/* ... */` block comments are supported anywhere
outside of string/hex/regex literals.

## Strings

| Form | Example | Notes |
|---|---|---|
| Text | `$a = "eval(" nocase wide ascii fullword` | `nocase`, `wide` (UTF-16LE), `ascii` (default on unless `wide` is given alone), `fullword` (boundary is any non-alphanumeric/`_` byte, or the buffer edge) |
| Hex | `$b = { 4D 5A ?? A? ?5 [2-4] [8] [3-] ( AA BB \| CC DD ) }` | `??` any byte; `A?`/`?5` nibble wildcards; `[n]`, `[n-m]`, `[n-]` jumps (unbounded jumps are capped at 512 bytes to bound worst-case matching cost); `( x \| y )` alternatives, which may themselves contain any of the above |
| Regex | `$c = /[A-Za-z0-9+\/]{40,}={0,2}/is` | Compiled with the `regex` crate's bytes API; `i` = case-insensitive, `s` = `.` matches newlines. Anchoring, character classes, quantifiers, and alternation follow standard `regex` crate syntax (a close superset of PCRE for this purpose), **not** PCRE backreferences/lookaround, which `regex` does not support. |

A string-level `private` modifier is accepted and parsed but has no
runtime effect (Wardex does not restrict which conditions may reference a
string).

## Conditions

Supported operators and constructs, with standard precedence
(`or` < `and` < `not` < comparisons):

- Boolean: `and`, `or`, `not`, parentheses.
- String presence: `$a` (true if `$a` matched anywhere).
- Counting: `#a`, compared with `== != > >= < <=`, e.g. `#a > 2`.
- Offsets: `@a[i]` (1-based index of the i-th match of `$a`), `$a at N`,
  `$a in (N..M)`.
- File size: `filesize`, with `KB`/`MB` suffixes (`filesize < 10MB`).
- Aggregate string sets: `all of them`, `any of them`, `N of them`,
  `N of ($a, $b)`, `N of ($prefix*)` (matches every declared string whose
  id starts with `prefix`).
- Absolute reads: `uint8(off)`, `uint16(off)`, `uint32(off)`, and their
  big-endian counterparts `uint8be`/`uint16be`/`uint32be`, each returning
  an integer you can compare (`uint16(0) == 0x5A4D`). Offsets may be
  simple `+`/`-` arithmetic over integer literals, `filesize`, `#a`,
  `@a[i]`, and nested `uint*` reads.
- Rule references: a bare identifier that names another rule (including a
  `private` one) evaluates to whether that rule matched. Rules are
  evaluated in file order, so a condition may only reference a rule
  defined **earlier** in the same file (matching the common
  helper-rule-first authoring convention); referencing an unknown rule, or
  one defined later, is a **compile error** rather than silently
  evaluating to `false`.

### What is intentionally not supported

Anything not listed above is a **compile error** with a line and column,
never a rule that loads and then silently mis-matches:

- Module-provided fields/functions (`pe.number_of_sections`,
  `hash.md5(...)`, etc.) — the modules above are accepted only so real
  rule files that merely `import` them do not fail to load; using their
  fields is a parse error (an unresolvable identifier/function call).
- `for` loops over string sets or arrays (`for any i in (...) : (...)`).
- External variables, rule sets (`.yc` compiled rules), and YARA's
  `include` directive.
- Backreferences and lookaround in regex strings (a `regex`-crate
  limitation, not a Wardex-specific one).

## Loading

- `YaraEngine::load_rules_yar(source)` / `load_rules_yar_file(path)` —
  compile and load a single `.yar` source string/file.
- `YaraEngine::load_rules_dir(dir)` — loads every `*.yar`/`*.yara` file in
  a directory (non-recursive); a bad file is reported but does not stop
  the rest from loading. Wardex calls this for `rules/yara/` at startup.
- `YaraEngine::load_rules_json(json)` — unchanged, still the way JSON rule
  packs (e.g. the bundled community malware pack) are loaded.

## Example

See `rules/yara/wardex_examples.yar` for small, original example rules
(not vendored from any third-party ruleset) exercising most of the syntax
above: text/hex/regex strings, modifiers, `at`/`in`, `N of (...)`,
`filesize`, and a private helper rule referenced from another rule.
