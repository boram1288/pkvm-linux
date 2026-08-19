/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef __ARM64_KVM_NVHE_PVM_DMA_SHARE_H__
#define __ARM64_KVM_NVHE_PVM_DMA_SHARE_H__

#include <nvhe/pkvm.h>

#define KVM_PVM_DMA_SHARE_EXPORT	3
#define KVM_PVM_DMA_SHARE_IMPORT	4
#define KVM_PVM_DMA_SHARE_RETURN	5
#define KVM_PVM_DMA_SHARE_REVOKE	6
#define KVM_PVM_DMA_SHARE_LEASE_QUERY	7
#define KVM_PVM_DMA_SHARE_EVENT_POLL	8
#define KVM_PVM_DMA_SHARE_ID_GET	9
#define KVM_PVM_MSG_SEND_BEGIN		10
#define KVM_PVM_MSG_SEND_CHUNK		11
#define KVM_PVM_MSG_SEND_COMMIT		12
#define KVM_PVM_MSG_RECV_INFO		13
#define KVM_PVM_MSG_RECV_CHUNK		14
#define KVM_PVM_MSG_RECV_POP		15
#define KVM_PVM_MSG_QUEUE_DEPTH		16

bool pkvm_pvm_dma_share_hvc(struct pkvm_hyp_vcpu *hyp_vcpu,
			    u64 *exit_code);
void pkvm_pvm_dma_share_teardown(struct pkvm_hyp_vm *vm);

#endif /* __ARM64_KVM_NVHE_PVM_DMA_SHARE_H__ */
