# ECDAT Member 2 — Data & Taxonomy Engineer

Member 2 provides the shared `CryptoAsset` contract, JSON serialization, a
YAML-driven taxonomy database, and the classification engine. It depends only
on the ECDAT core types; it has **no dependency on Members 1, 3, or 4**.

```
CryptoAsset                      (core/..., shared contract)
     |
     v
JSON serialization               (core/...)
     |
     v
TaxonomyDB                       (taxonomy/..., loaded from taxonomy.yaml)
     |
     v
Classifier                       (taxonomy/...)
     |
     v
Status + risk_score + pqc_flag
```

## Layout

```
taxonomy/
├── CMakeLists.txt
├── core/
│   ├── include/ecdat/{types,serialization}.hpp
│   ├── src/serialization.cpp
│   └── tests/test_serialization.cpp
└── taxonomy/
    ├── include/ecdat/taxonomy.hpp
    ├── src/{taxonomy_loader,classifier}.cpp
    ├── data/taxonomy.yaml
    └── tests/{test_taxonomy,test_classifier}.cpp
```

## Taxonomy schema

`taxonomy/data/taxonomy.yaml` is the **source of truth** for algorithm
metadata. Adding/removing/modifying an algorithm there requires **no C++
change**. Each entry:

| Field                  | Type   | Required | Meaning |
|------------------------|--------|----------|---------|
| `name`                 | string | yes      | Display name (unique after normalization) |
| `type`                 | string | yes      | `symmetric`, `asymmetric`, `hash`, `signature`, `key-exchange`, ... |
| `status`               | string | yes      | `Safe`, `Weak`, `Deprecated`, `Unknown` |
| `risk_base`            | number | yes      | Base risk in `[0,10]` |
| `pqc_vulnerable`       | bool   | yes      | Threatened by quantum computing |
| `replacement`          | string | no       | Recommended upgrade; empty = none |
| `min_secure_key_bits`  | int    | no       | Downgrade if `key_size` (when >0) is below this |
| `weak_curves`          | list   | no       | Curves (case-insensitive) that trigger a downgrade |

## Classification precedence (deterministic)

1. **Explicit security/key/curve override** — if the recognized algorithm's
   key size or curve is below its taxonomy threshold, force status to at
   least `Weak` and add `+2.0` to the risk score.
2. **Taxonomy lookup** — status/risk/pqc come from the matching entry.
3. **Unknown fallback** — an algorithm not present in the taxonomy yields
   `Status::Unknown`, risk `0.0`, and `pqc_flag = false`. Unknown PQC safety
   is never guessed.

### Key / curve overrides

* `min_secure_key_bits`: e.g. RSA threshold 2048 → `RSA` with 1024-bit keys is
  downgraded (Weak, `+2.0`). A `key_size` of 0 (unknown) is never downgraded.
* `weak_curves`: e.g. `ECDSA` on `P-192` is downgraded.

### Risk-score logic

```
raw = risk_base            (from taxonomy, clamped to [0,10])
if downgrade: raw += 2.0
final = clamp(raw, 0.0, 10.0)
```

Scores can never be negative or exceed 10.

### Unknown algorithm behavior

Never guessed. Unknown algorithms are classified `Unknown` with zero risk and
no PQC claim, and remain explicitly marked as not-in-taxonomy via
`Classification::entry == nullptr`.

### Duplicate YAML behavior

Duplicate (after-normalization) algorithm names are allowed; the **last**
occurrence wins and overwrites the earlier one.

### Case-insensitive lookup

Lookup keys are normalized (whitespace-trimmed, lower-cased) centrally in
`normalize_key` and in `TaxonomyDB::lookup`. `RSA`, `rsa`, `RsA`, `rSa` all
resolve identically; the original display name is preserved in each entry.

## Public API

**Core (`ecdat/types.hpp`, `ecdat/serialization.hpp`)**

```cpp
enum class Status { Safe, Weak, Deprecated, Unknown };
struct CryptoAsset { /* source_type, file, line, algorithm, key_size, curve,
                        context, status, risk_score, pqc_flag */ };
struct Finding { CryptoAsset asset; std::string message; };

std::string_view status_to_string(Status);
std::optional<Status> status_from_string(std::string_view);

nlohmann::json to_json(const CryptoAsset&);
std::optional<CryptoAsset> from_json(const nlohmann::json&);
std::optional<CryptoAsset> parse_asset(std::string_view);
```

**Taxonomy / classifier (`ecdat/taxonomy.hpp`)**

```cpp
struct TaxonomyEntry { /* name, type, status, risk_base, pqc_vulnerable,
                          replacement, min_secure_key_bits, weak_curves */ };
class TaxonomyDB {
  static TaxonomyDB load_from_file(const std::string& path);
  static TaxonomyDB load_from_string(std::string_view yaml);
  const TaxonomyEntry* lookup(std::string_view name) const; // case-insensitive
  std::size_t size() const; bool empty() const;
};
std::string normalize_key(std::string_view);

struct Classification { Status status; double risk_score; bool pqc_flag;
                        const TaxonomyEntry* entry; };
Classification classify_asset(const CryptoAsset&, const TaxonomyDB&);
Status classify(const CryptoAsset&, const TaxonomyDB&);
```

Malformed YAML/JSON never crashes the program:
* `parse_asset` returns `std::nullopt` on malformed JSON.
* `from_json` requires a valid `algorithm` and rejects wrong-typed fields.
* `TaxonomyDB::load_*` throw `std::runtime_error` with a descriptive message.

## Build & test

```sh
cmake -S . -B build -G Ninja -DCMAKE_BUILD_TYPE=Release
cmake --build build
ctest --test-dir build --output-on-failure
```

Sanitizer (ASan + UBSan) build:

```sh
cmake -S . -B build-sanitize -G Ninja -DCMAKE_BUILD_TYPE=Debug \
      -DECDAT_ENABLE_SANITIZERS=ON
cmake --build build-sanitize
ctest --test-dir build-sanitize --output-on-failure
```

## Notes / decisions

* Empty taxonomy documents are tolerated as an empty database (safe, explicit).
* `key_size == 0` is treated as "unknown" and never triggers a size downgrade.
* Optional fields in JSON missing → defaults; present-but-wrong-type → reject.
* An empty `status`/`algorithm` string is not a valid algorithm and is treated
  as unknown by the classifier.