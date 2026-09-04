#pragma once
// ============================================================
// ECDAT Shared Contract — types.hpp (Member 1 shim)
// ============================================================
//
// The AUTHORITATIVE ECDAT shared contract (CryptoAsset, Status, Finding) is
// owned by Member 2 in taxonomy/core/include/ecdat/types.hpp. That is the ONE
// definition all members compile against (frozen contract).
//
// Member 1 previously defined duplicates of ecdat::CryptoAsset, ecdat::Status
// and ecdat::Finding here, which caused ODR conflicts with Member 2. Those are
// removed. This header now merely re-exports the authoritative contract and
// keeps only Member-1-specific role additions that the authoritative header
// does not define.
//
// Do not redefine CryptoAsset / Status / Finding here.

#include "ecdat/types.hpp"

namespace ecdat {

// Member 1/4 role-specific severity level. Not part of the Member 2 contract;
// used by later reporting/explainability layers.
enum class Severity {
    Low,
    Medium,
    High,
    Critical
};

} // namespace ecdat
