// SPDX-License-Identifier: MIT
// Copyright (c) 2024 Praxis Contributors

//! Offline transpiler from Kuadrant `AuthPolicy` resources to Praxis
//! policy-filter configuration + a CPEX policy document.
//!
//! This is the Phase A (mapping-feasibility) surface of the `AuthPolicy`
//! support spike: it parses the supported subset of `AuthPolicy`
//! (`kuadrant.io/v1`, targeting Authorino `v1beta3`) and translates it
//! best-effort, emitting a structured coverage report. No proxy runtime
//! is involved; see `docs/plans/2026-06-28-001-feat-authpolicy-transpiler-and-http-authz-plan.md`.

// The model is a faithful representation of the AuthPolicy schema; not
// every parsed field is consumed by the translator (e.g. tracing-only or
// reported-as-gap fields), and the module is wired into a subcommand in a
// later unit. Allow dead code across the transpiler module during the spike.
#![allow(dead_code, reason = "faithful data model; not all fields are consumed")]
// The AuthPolicy schema is a deep, nested config model; the derived
// Deserialize methods have large (but cold) stack frames. This is expected
// for faithful config types and not a hot path.
#![allow(clippy::large_stack_frames, reason = "faithful nested config model")]

pub(crate) mod model;
