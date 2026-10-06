//! Background job system
//!
//! This module provides a trait-based background job processing system
//! with support for multiple queue backends (in-memory, Redis) and
//! distributed worker pools.

mod config;
mod in_memory;
mod registry;
mod scheduler;
mod worker;

#[cfg(feature = "jobs-redis")]
mod redis;

#[cfg(test)]
mod tests;

pub use config::{JobBackend, JobsConfig};
pub use in_memory::InMemoryJobQueue;
pub use registry::JobRegistry;
pub use scheduler::{
    DEFAULT_SCHEDULER_LOCK_TTL, InMemorySchedulerLock, JobScheduler, SCHEDULER_LOCK_KEY_PREFIX,
    SchedulerHandle, SchedulerLock,
};
pub use worker::{JobWorker, WorkerPool};

#[cfg(feature = "jobs-redis")]
pub use redis::RedisJobQueue;
#[cfg(feature = "jobs-redis")]
pub use scheduler::RedisSchedulerLock;
