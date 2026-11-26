// SPDX-License-Identifier: Apache-2.0

pub mod access;
mod affinity;
pub mod auth;
pub mod catalog;
pub mod config;
pub mod database;
mod events;
pub mod gateway;
mod identity;
pub mod jwt;
mod legacy_sse;
pub mod mcp;
mod modern;
mod modern_validation;
pub mod probes;
mod redis_events;
mod redis_sessions;
mod resource_relay;
mod sessions;
mod subscriptions;
pub mod upstream;
mod websocket;
