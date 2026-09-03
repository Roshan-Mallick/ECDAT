// pqc.h
//
// ECDAT Member 3 - PQC Intelligence umbrella header.
//
// Aggregates the PQC-related Member 3 modules:
//   - migration.h   (role-aware PQC replacement mapping)
//   - readiness.h   (PQC readiness percentage)
//   - explanation.h (What / Where / Why / Action)
//
// These modules consume the authoritative Member 2 taxonomy (via the shared
// CryptoAsset contract and Classification) rather than maintaining a second
// source of truth.

#pragma once

#include "migration.h"
#include "readiness.h"
#include "explanation.h"
