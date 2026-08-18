/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef __ARM64_KVM_NVHE_PVM_DMA_SHARE_H__
#define __ARM64_KVM_NVHE_PVM_DMA_SHARE_H__

#include <nvhe/pkvm.h>

bool pkvm_pvm_dma_share_hvc(struct pkvm_hyp_vcpu *hyp_vcpu,
			    u64 *exit_code);
void pkvm_pvm_dma_share_teardown(struct pkvm_hyp_vm *vm);

#endif /* __ARM64_KVM_NVHE_PVM_DMA_SHARE_H__ */
