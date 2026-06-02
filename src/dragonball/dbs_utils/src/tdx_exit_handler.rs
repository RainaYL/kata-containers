// Copyright (c) 2026 Ant Group
//
// SPDX-License-Identifier: Apache-2.0
//

use threadpool::ThreadPool;

const THREAD_POOL_SIZE_DEFAULT: usize = 4;

/// Handler for VCPU exit type: KVM_EXIT_TDX
pub struct TdxExitHandler {
    thread_pool: ThreadPool,
    event_notify_vector: u8,
}

impl TdxExitHandler {
    pub fn new(thread_pool_size: usize) -> Self {
        Self {
            thread_pool: ThreadPool::with_name("tdxquote-thread".to_string(), thread_pool_size),
            event_notify_vector: 0,
        }
    }
}

impl Default for TdxExitHandler {
    fn default() -> TdxExitHandler {
        Self::new(THREAD_POOL_SIZE_DEFAULT)
    }
}
