// Copyright (C) 2023 Alibaba Cloud. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

#[cfg(target_arch = "x86_64")]
pub mod tdx_ioctls;

pub const KVM_X86_TDX_VM: u64 = 5;

pub const KVM_TDX_MEASURE_MEMORY_REGION: u32 = 1u32 << 0;
