// SPDX-License-Identifier: GPL-2.0-only
/*
 * Minimal EL2-mediated protected-VM peer DMA sharing for the Phase 08 PoC.
 *
 * The owner keeps CPU ownership of the page. EL2 pins the page and installs a
 * read-only mapping directly in the approved receiver's protected IOMMU
 * domain. No Host stage-2 or Host IOMMU mapping is created.
 */

#include <linux/arm-smccc.h>
#include <linux/iommu.h>
#include <linux/mm.h>

#include <asm/stage2_pgtable.h>

#include <kvm/arm_hypercalls.h>

#include <nvhe/iommu.h>
#include <nvhe/mem_protect.h>
#include <nvhe/pkvm.h>
#include <nvhe/pviommu.h>
#include <nvhe/pviommu-host.h>
#include <nvhe/pvm-dma-share.h>

struct pvm_dma_share {
	struct pkvm_hyp_vm *owner;
	struct pkvm_hyp_vm *receiver;
	phys_addr_t pa;
	size_t dma_ref_size;
	pkvm_handle_t receiver_domain;
	unsigned long receiver_iova;
	u64 token;
	u32 receiver_sid;
	bool mapped;
};

static DEFINE_HYP_SPINLOCK(pvm_dma_share_lock);
static struct pvm_dma_share pvm_dma_share;

/*
 * CPU-visible cross-pVM lease used by Phase 09.  Unlike the Phase 08 DMA
 * grant above, this lease moves a guest stage-2 mapping and never maps the
 * backing page into Host stage-2.
 */
struct pvm_cpu_lease {
	struct pkvm_hyp_vcpu *owner_vcpu;
	struct pkvm_hyp_vm *owner;
	struct pkvm_hyp_vm *receiver;
	phys_addr_t pa;
	u64 owner_ipa;
	u64 receiver_ipa;
	u64 token;
	u32 receiver_endpoint;
	bool event_pending;
	bool mapped;
};

static struct pvm_cpu_lease pvm_cpu_lease;
static u64 pvm_cpu_next_token = 0x504b564d00000000ULL;

#define PVM_MSG_MAX_ENDPOINT 2
#define PVM_MSG_MAX_SIZE 256
#define PVM_MSG_QUEUE_SIZE 64
#define PVM_MSG_CHUNK_SIZE 24
#define PVM_MSG_RET_QUEUE_FULL (-4)

struct pvm_msg_entry {
	u32 sender;
	u32 len;
	u64 sequence;
	u8 data[PVM_MSG_MAX_SIZE];
};

struct pvm_msg_queue {
	u32 head;
	u32 count;
	struct pvm_msg_entry entries[PVM_MSG_QUEUE_SIZE];
};

struct pvm_msg_staging {
	bool active;
	u32 receiver;
	u32 len;
	u32 written;
	u8 data[PVM_MSG_MAX_SIZE];
};

static struct pvm_msg_queue pvm_msg_queues[PVM_MSG_MAX_ENDPOINT + 1];
static struct pvm_msg_staging pvm_msg_staging[PVM_MSG_MAX_ENDPOINT + 1];
static u64 pvm_msg_sequence;

static bool pvm_msg_endpoint_valid(u32 endpoint)
{
	return endpoint > 0 && endpoint <= PVM_MSG_MAX_ENDPOINT;
}

static bool pvm_msg_peer_allowed(u32 sender, u32 receiver)
{
	return pvm_msg_endpoint_valid(sender) && pvm_msg_endpoint_valid(receiver) &&
	       sender != receiver;
}

static bool pvm_msg_send_begin(struct pkvm_hyp_vcpu *hyp_vcpu)
{
	struct kvm_vcpu *vcpu = &hyp_vcpu->vcpu;
	u32 sender = hyp_vcpu_to_endpoint_id(hyp_vcpu);
	u32 receiver = smccc_get_arg2(vcpu);
	u32 len = smccc_get_arg3(vcpu);
	struct pvm_msg_staging *staging;

	if (!pvm_msg_peer_allowed(sender, receiver) || !len || len > PVM_MSG_MAX_SIZE)
		goto invalid;
	hyp_spin_lock(&pvm_dma_share_lock);
	staging = &pvm_msg_staging[sender];
	if (staging->active) {
		hyp_spin_unlock(&pvm_dma_share_lock);
		goto invalid;
	}
	memset(staging, 0, sizeof(*staging));
	staging->active = true;
	staging->receiver = receiver;
	staging->len = len;
	hyp_spin_unlock(&pvm_dma_share_lock);
	smccc_set_retval(vcpu, SMCCC_RET_SUCCESS, 0, 0, 0);
	return true;
invalid:
	smccc_set_retval(vcpu, SMCCC_RET_INVALID_PARAMETER, 0, 0, 0);
	return true;
}

static bool pvm_msg_send_chunk(struct pkvm_hyp_vcpu *hyp_vcpu)
{
	struct kvm_vcpu *vcpu = &hyp_vcpu->vcpu;
	u32 sender = hyp_vcpu_to_endpoint_id(hyp_vcpu);
	u32 offset = smccc_get_arg2(vcpu);
	u64 words[3] = { smccc_get_arg3(vcpu), smccc_get_arg4(vcpu), smccc_get_arg5(vcpu) };
	struct pvm_msg_staging *staging;
	u32 len;

	if (!pvm_msg_endpoint_valid(sender))
		goto invalid;
	hyp_spin_lock(&pvm_dma_share_lock);
	staging = &pvm_msg_staging[sender];
	if (!staging->active || offset != staging->written || offset >= staging->len)
		goto invalid_locked;
	len = min_t(u32, PVM_MSG_CHUNK_SIZE, staging->len - offset);
	memcpy(staging->data + offset, words, len);
	staging->written += len;
	hyp_spin_unlock(&pvm_dma_share_lock);
	smccc_set_retval(vcpu, SMCCC_RET_SUCCESS, len, 0, 0);
	return true;
invalid_locked:
	hyp_spin_unlock(&pvm_dma_share_lock);
invalid:
	smccc_set_retval(vcpu, SMCCC_RET_INVALID_PARAMETER, 0, 0, 0);
	return true;
}

static bool pvm_msg_send_commit(struct pkvm_hyp_vcpu *hyp_vcpu)
{
	struct kvm_vcpu *vcpu = &hyp_vcpu->vcpu;
	u32 sender = hyp_vcpu_to_endpoint_id(hyp_vcpu);
	struct pvm_msg_staging *staging;
	struct pvm_msg_queue *queue;
	struct pvm_msg_entry *entry;
	u64 sequence;

	if (!pvm_msg_endpoint_valid(sender))
		goto invalid;
	hyp_spin_lock(&pvm_dma_share_lock);
	staging = &pvm_msg_staging[sender];
	if (!staging->active || staging->written != staging->len)
		goto invalid_locked;
	queue = &pvm_msg_queues[staging->receiver];
	if (queue->count == PVM_MSG_QUEUE_SIZE) {
		memset(staging, 0, sizeof(*staging));
		hyp_spin_unlock(&pvm_dma_share_lock);
		smccc_set_retval(vcpu, PVM_MSG_RET_QUEUE_FULL, 0, 0, 0);
		return true;
	}
	entry = &queue->entries[(queue->head + queue->count) % PVM_MSG_QUEUE_SIZE];
	memset(entry, 0, sizeof(*entry));
	entry->sender = sender;
	entry->len = staging->len;
	sequence = ++pvm_msg_sequence;
	entry->sequence = sequence;
	memcpy(entry->data, staging->data, staging->len);
	queue->count++;
	memset(staging, 0, sizeof(*staging));
	hyp_spin_unlock(&pvm_dma_share_lock);
	smccc_set_retval(vcpu, SMCCC_RET_SUCCESS, sequence, 0, 0);
	return true;
invalid_locked:
	hyp_spin_unlock(&pvm_dma_share_lock);
invalid:
	smccc_set_retval(vcpu, SMCCC_RET_INVALID_PARAMETER, 0, 0, 0);
	return true;
}

static bool pvm_msg_recv_info(struct pkvm_hyp_vcpu *hyp_vcpu)
{
	struct kvm_vcpu *vcpu = &hyp_vcpu->vcpu;
	u32 receiver = hyp_vcpu_to_endpoint_id(hyp_vcpu);
	struct pvm_msg_queue *queue;
	struct pvm_msg_entry *entry;

	if (!pvm_msg_endpoint_valid(receiver))
		goto invalid;
	hyp_spin_lock(&pvm_dma_share_lock);
	queue = &pvm_msg_queues[receiver];
	if (!queue->count)
		goto invalid_locked;
	entry = &queue->entries[queue->head];
	smccc_set_retval(vcpu, SMCCC_RET_SUCCESS, entry->sender, entry->len,
			 entry->sequence);
	__kvm_inject_el1_irq_live(vcpu);
	hyp_spin_unlock(&pvm_dma_share_lock);
	return true;
invalid_locked:
	hyp_spin_unlock(&pvm_dma_share_lock);
invalid:
	smccc_set_retval(vcpu, SMCCC_RET_INVALID_PARAMETER, 0, 0, 0);
	return true;
}

static bool pvm_msg_recv_chunk(struct pkvm_hyp_vcpu *hyp_vcpu)
{
	struct kvm_vcpu *vcpu = &hyp_vcpu->vcpu;
	u32 receiver = hyp_vcpu_to_endpoint_id(hyp_vcpu);
	u32 offset = smccc_get_arg2(vcpu);
	struct pvm_msg_queue *queue;
	struct pvm_msg_entry *entry;
	u64 words[3] = { 0 };
	u32 len;

	if (!pvm_msg_endpoint_valid(receiver))
		goto invalid;
	hyp_spin_lock(&pvm_dma_share_lock);
	queue = &pvm_msg_queues[receiver];
	if (!queue->count)
		goto invalid_locked;
	entry = &queue->entries[queue->head];
	if (offset >= entry->len)
		goto invalid_locked;
	len = min_t(u32, PVM_MSG_CHUNK_SIZE, entry->len - offset);
	memcpy(words, entry->data + offset, len);
	smccc_set_retval(vcpu, SMCCC_RET_SUCCESS, words[0], words[1], words[2]);
	hyp_spin_unlock(&pvm_dma_share_lock);
	return true;
invalid_locked:
	hyp_spin_unlock(&pvm_dma_share_lock);
invalid:
	smccc_set_retval(vcpu, SMCCC_RET_INVALID_PARAMETER, 0, 0, 0);
	return true;
}

static bool pvm_msg_recv_pop(struct pkvm_hyp_vcpu *hyp_vcpu)
{
	struct kvm_vcpu *vcpu = &hyp_vcpu->vcpu;
	u32 receiver = hyp_vcpu_to_endpoint_id(hyp_vcpu);
	struct pvm_msg_queue *queue;

	if (!pvm_msg_endpoint_valid(receiver))
		goto invalid;
	hyp_spin_lock(&pvm_dma_share_lock);
	queue = &pvm_msg_queues[receiver];
	if (!queue->count)
		goto invalid_locked;
	memset(&queue->entries[queue->head], 0, sizeof(queue->entries[0]));
	queue->head = (queue->head + 1) % PVM_MSG_QUEUE_SIZE;
	queue->count--;
	hyp_spin_unlock(&pvm_dma_share_lock);
	smccc_set_retval(vcpu, SMCCC_RET_SUCCESS, 0, 0, 0);
	return true;
invalid_locked:
	hyp_spin_unlock(&pvm_dma_share_lock);
invalid:
	smccc_set_retval(vcpu, SMCCC_RET_INVALID_PARAMETER, 0, 0, 0);
	return true;
}

static bool pvm_msg_queue_depth(struct pkvm_hyp_vcpu *hyp_vcpu)
{
	struct kvm_vcpu *vcpu = &hyp_vcpu->vcpu;
	u32 endpoint = hyp_vcpu_to_endpoint_id(hyp_vcpu);
	u32 count;
	if (!pvm_msg_endpoint_valid(endpoint))
		goto invalid;
	hyp_spin_lock(&pvm_dma_share_lock);
	count = pvm_msg_queues[endpoint].count;
	hyp_spin_unlock(&pvm_dma_share_lock);
	smccc_set_retval(vcpu, SMCCC_RET_SUCCESS, count, PVM_MSG_QUEUE_SIZE, 0);
	return true;
invalid:
	smccc_set_retval(vcpu, SMCCC_RET_INVALID_PARAMETER, 0, 0, 0);
	return true;
}

static bool pvm_dma_share_has_request(struct kvm_vcpu *vcpu)
{
	return vcpu->arch.hyp_reqs->type != KVM_HYP_LAST_REQ;
}

static int pvm_cpu_lease_memcache_ready(struct pkvm_hyp_vcpu *hyp_vcpu,
					u64 *exit_code)
{
	struct kvm_vcpu *vcpu = &hyp_vcpu->vcpu;
	struct kvm_hyp_req *req;
	unsigned long min_pages;

	min_pages = kvm_mmu_cache_min_pages(&vcpu->kvm->arch.mmu);
	if (vcpu->arch.stage2_mc.nr_pages >= min_pages)
		return true;

	req = pkvm_hyp_req_reserve(hyp_vcpu, KVM_HYP_REQ_TYPE_MEM);
	if (!req)
		return -ENOMEM;
	req->memcache.dest = REQ_MEM_DEST_VCPU_MEMCACHE;
	req->memcache.nr_pages = min_pages;
	write_sysreg_el2(read_sysreg_el2(SYS_ELR) - 4, SYS_ELR);
	*exit_code = ARM_EXCEPTION_HYP_REQ;

	return false;
}

static void __pvm_dma_share_revoke(void)
{
	if (pvm_dma_share.mapped)
		WARN_ON(kvm_iommu_unmap_pages_for_vm(
					      pvm_dma_share.receiver,
					      pvm_dma_share.receiver_domain,
					      pvm_dma_share.receiver_iova,
					      PAGE_SIZE, 1) != PAGE_SIZE);
	WARN_ON(__pkvm_unuse_dma(pvm_dma_share.pa,
				 pvm_dma_share.dma_ref_size, NULL));
	memset(&pvm_dma_share, 0, sizeof(pvm_dma_share));
}

static void __pvm_cpu_lease_revoke(struct pkvm_hyp_vm *teardown_vm)
{
	int ret;

	if (!pvm_cpu_lease.owner ||
	    (pvm_cpu_lease.owner != teardown_vm &&
	     pvm_cpu_lease.receiver != teardown_vm))
		return;

	if (pvm_cpu_lease.mapped) {
		/* Restore owner stage-2 so normal owner teardown can reclaim it. */
		ret = __pkvm_guest_return_page(pvm_cpu_lease.owner_vcpu,
						pvm_cpu_lease.owner_ipa,
						pvm_cpu_lease.receiver,
						pvm_cpu_lease.receiver_ipa,
						pvm_cpu_lease.pa);
		WARN_ON(ret);
	}
	memset(&pvm_cpu_lease, 0, sizeof(pvm_cpu_lease));
}

static bool pvm_dma_share_grant(struct pkvm_hyp_vcpu *hyp_vcpu,
				u64 *exit_code)
{
	struct kvm_vcpu *vcpu = &hyp_vcpu->vcpu;
	struct pkvm_hyp_vm *vm = pkvm_hyp_vcpu_to_hyp_vm(hyp_vcpu);
	u64 ipa = smccc_get_arg2(vcpu);
	u64 size = smccc_get_arg3(vcpu);
	u64 receiver_sid = smccc_get_arg4(vcpu);
	phys_addr_t pa;
	size_t dma_ref_size;
	s8 level;
	int ret;

	if (!PAGE_ALIGNED(ipa) || size != PAGE_SIZE || receiver_sid > U32_MAX ||
	    smccc_get_arg5(vcpu) || smccc_get_arg6(vcpu))
		goto invalid;

	hyp_spin_lock(&pvm_dma_share_lock);
	if (pvm_dma_share.owner) {
		hyp_spin_unlock(&pvm_dma_share_lock);
		goto invalid;
	}
	hyp_spin_unlock(&pvm_dma_share_lock);

	ret = pkvm_get_guest_pa_request_use_dma(hyp_vcpu, ipa, size, &pa, &level);
	if (ret == -ENOENT) {
		*exit_code = ARM_EXCEPTION_HYP_REQ;
		return false;
	}
	if (ret)
		goto invalid;
	dma_ref_size = kvm_granule_size(level);

	hyp_spin_lock(&pvm_dma_share_lock);
	if (pvm_dma_share.owner) {
		hyp_spin_unlock(&pvm_dma_share_lock);
		WARN_ON(__pkvm_unuse_dma(pa, dma_ref_size, hyp_vcpu));
		goto invalid;
	}
	pvm_dma_share.owner = vm;
	pvm_dma_share.pa = pa;
	pvm_dma_share.dma_ref_size = dma_ref_size;
	pvm_dma_share.receiver_sid = receiver_sid;
	/* Single-slot PoC identifier; authorization is the receiver physical SID. */
	pvm_dma_share.token = 1;
	smccc_set_retval(vcpu, SMCCC_RET_SUCCESS, pvm_dma_share.token, 0, 0);
	hyp_spin_unlock(&pvm_dma_share_lock);
	return true;

invalid:
	smccc_set_retval(vcpu, SMCCC_RET_INVALID_PARAMETER, 0, 0, 0);
	return true;
}

static bool pvm_dma_share_accept(struct pkvm_hyp_vcpu *hyp_vcpu,
				 u64 *exit_code)
{
	struct kvm_vcpu *vcpu = &hyp_vcpu->vcpu;
	struct pkvm_hyp_vm *vm = pkvm_hyp_vcpu_to_hyp_vm(hyp_vcpu);
	u64 token = smccc_get_arg2(vcpu);
	pkvm_handle_t domain = smccc_get_arg3(vcpu);
	pkvm_handle_t pviommu = smccc_get_arg4(vcpu);
	u64 vsid = smccc_get_arg5(vcpu);
	unsigned long iova = smccc_get_arg6(vcpu);
	struct pviommu_route route;
	unsigned long mapped = 0;
	int ret;

	if (!token || vsid > U32_MAX || !PAGE_ALIGNED(iova) ||
	    !pkvm_guest_iommu_domain_owned(vm, domain) ||
	    pkvm_pviommu_get_route(vm, pviommu, vsid, &route))
		goto invalid;

	refill_hyp_pool(&vm->iommu_pool, &hyp_vcpu->host_vcpu->arch.iommu_mc);
	hyp_spin_lock(&pvm_dma_share_lock);
	if (!pvm_dma_share.owner || pvm_dma_share.mapped ||
	    pvm_dma_share.token != token ||
	    pvm_dma_share.receiver_sid != route.sid) {
		hyp_spin_unlock(&pvm_dma_share_lock);
		goto invalid;
	}

	ret = kvm_iommu_map_pages(domain, iova, pvm_dma_share.pa,
				  PAGE_SIZE, 1, IOMMU_READ, &mapped);
	if (!mapped && pvm_dma_share_has_request(vcpu)) {
		hyp_spin_unlock(&pvm_dma_share_lock);
		*exit_code = ARM_EXCEPTION_HYP_REQ;
		return false;
	}
	if (ret || mapped != PAGE_SIZE) {
		if (mapped)
			WARN_ON(kvm_iommu_unmap_pages(domain, iova,
						      PAGE_SIZE, 1) != mapped);
		hyp_spin_unlock(&pvm_dma_share_lock);
		goto invalid;
	}

	pvm_dma_share.receiver = vm;
	pvm_dma_share.receiver_domain = domain;
	pvm_dma_share.receiver_iova = iova;
	pvm_dma_share.mapped = true;
	smccc_set_retval(vcpu, SMCCC_RET_SUCCESS, PAGE_SIZE, 0, 0);
	hyp_spin_unlock(&pvm_dma_share_lock);
	return true;

invalid:
	smccc_set_retval(vcpu, SMCCC_RET_INVALID_PARAMETER, 0, 0, 0);
	return true;
}

static bool pvm_dma_share_query(struct pkvm_hyp_vcpu *hyp_vcpu)
{
	struct kvm_vcpu *vcpu = &hyp_vcpu->vcpu;
	struct pkvm_hyp_vm *vm = pkvm_hyp_vcpu_to_hyp_vm(hyp_vcpu);
	u64 token = smccc_get_arg2(vcpu);
	bool active;

	if (smccc_get_arg3(vcpu) || smccc_get_arg4(vcpu) ||
	    smccc_get_arg5(vcpu) || smccc_get_arg6(vcpu))
		goto invalid;

	hyp_spin_lock(&pvm_dma_share_lock);
	active = pvm_dma_share.mapped && pvm_dma_share.receiver == vm &&
		 pvm_dma_share.token == token;
	hyp_spin_unlock(&pvm_dma_share_lock);
	if (!active)
		goto invalid;

	smccc_set_retval(vcpu, SMCCC_RET_SUCCESS, PAGE_SIZE, 0, 0);
	return true;

invalid:
	smccc_set_retval(vcpu, SMCCC_RET_INVALID_PARAMETER, 0, 0, 0);
	return true;
}

static bool pvm_cpu_lease_export(struct pkvm_hyp_vcpu *hyp_vcpu,
				 u64 *exit_code)
{
	struct kvm_vcpu *vcpu = &hyp_vcpu->vcpu;
	struct pkvm_hyp_vm *vm = pkvm_hyp_vcpu_to_hyp_vm(hyp_vcpu);
	u64 owner_ipa = smccc_get_arg2(vcpu);
	u64 receiver_endpoint = smccc_get_arg3(vcpu);
	u64 size = smccc_get_arg4(vcpu);
	u64 pa;
	s8 level;
	struct pkvm_hyp_vm *receiver;
	int ret;

	if (!PAGE_ALIGNED(owner_ipa) || size != PAGE_SIZE ||
	    !receiver_endpoint ||
	    receiver_endpoint == hyp_vcpu_to_endpoint_id(hyp_vcpu) ||
	    smccc_get_arg5(vcpu) || smccc_get_arg6(vcpu))
		goto invalid;

	hyp_spin_lock(&pvm_dma_share_lock);
	if (pvm_cpu_lease.owner) {
		hyp_spin_unlock(&pvm_dma_share_lock);
		goto invalid;
	}
	hyp_spin_unlock(&pvm_dma_share_lock);

	ret = pkvm_get_guest_pa_request(hyp_vcpu, owner_ipa, PAGE_SIZE, &pa, &level);
	if (ret == -ENOENT) {
		*exit_code = ARM_EXCEPTION_HYP_REQ;
		return false;
	}
	if (ret)
		goto invalid;
	if (kvm_granule_size(level) != PAGE_SIZE) {
		int cache_ready;

		/*
		 * Ordinary guest RAM is usually populated as PMD-level
		 * stage-2 blocks. Split the covering block into page-level
		 * entries so a single 4 KiB page can move to the receiver
		 * without disturbing the rest of the block.
		 */
		if (kvm_granule_size(level) != PMD_SIZE)
			goto invalid;
		cache_ready = pvm_cpu_lease_memcache_ready(hyp_vcpu, exit_code);
		if (cache_ready < 0)
			goto invalid;
		if (!cache_ready)
			return false;
		ret = __pkvm_host_split_guest(
			ALIGN_DOWN(owner_ipa, PMD_SIZE) >> PAGE_SHIFT,
			PMD_SIZE, hyp_vcpu);
		if (ret)
			goto invalid;
		ret = pkvm_get_guest_pa_request(hyp_vcpu, owner_ipa, PAGE_SIZE,
						&pa, &level);
		if (ret || kvm_granule_size(level) != PAGE_SIZE)
			goto invalid;
	}

	hyp_spin_lock(&pvm_dma_share_lock);
	if (pvm_cpu_lease.owner) {
		hyp_spin_unlock(&pvm_dma_share_lock);
		goto invalid;
	}
	receiver = pkvm_get_hyp_vm_by_endpoint_id(receiver_endpoint);
	if (!receiver || receiver == vm) {
		hyp_spin_unlock(&pvm_dma_share_lock);
		goto invalid;
	}
	pvm_cpu_lease.owner_vcpu = hyp_vcpu;
	pvm_cpu_lease.owner = vm;
	pvm_cpu_lease.receiver = receiver;
	pvm_cpu_lease.pa = pa;
	pvm_cpu_lease.owner_ipa = owner_ipa;
	pvm_cpu_lease.receiver_endpoint = receiver_endpoint;
	pvm_cpu_lease.token = ++pvm_cpu_next_token;
	pvm_cpu_lease.event_pending = true;
	smccc_set_retval(vcpu, SMCCC_RET_SUCCESS, pvm_cpu_lease.token, 0, 0);
	hyp_spin_unlock(&pvm_dma_share_lock);
	return true;

invalid:
	smccc_set_retval(vcpu, SMCCC_RET_INVALID_PARAMETER, 0, 0, 0);
	return true;
}

static bool pvm_cpu_lease_import(struct pkvm_hyp_vcpu *hyp_vcpu,
				 u64 *exit_code)
{
	struct kvm_vcpu *vcpu = &hyp_vcpu->vcpu;
	struct pkvm_hyp_vm *vm = pkvm_hyp_vcpu_to_hyp_vm(hyp_vcpu);
	u64 token = smccc_get_arg2(vcpu);
	u64 receiver_ipa = smccc_get_arg3(vcpu);
	phys_addr_t pa;
	int ret, cache_ready;

	if (!token || !PAGE_ALIGNED(receiver_ipa))
		goto invalid;
	cache_ready = pvm_cpu_lease_memcache_ready(hyp_vcpu, exit_code);
	if (cache_ready < 0)
		goto invalid;
	if (!cache_ready)
		return false;
	hyp_spin_lock(&pvm_dma_share_lock);
	if (!pvm_cpu_lease.owner || pvm_cpu_lease.mapped ||
	    pvm_cpu_lease.token != token ||
	    pvm_cpu_lease.receiver != vm ||
	    pvm_cpu_lease.receiver_endpoint != hyp_vcpu_to_endpoint_id(hyp_vcpu)) {
		hyp_spin_unlock(&pvm_dma_share_lock);
		goto invalid;
	}
	ret = __pkvm_guest_export_page(pvm_cpu_lease.owner_vcpu,
					pvm_cpu_lease.owner_ipa, vm, receiver_ipa,
					&vcpu->arch.stage2_mc, &pa);
	if (!ret && pa == pvm_cpu_lease.pa) {
		pvm_cpu_lease.receiver_ipa = receiver_ipa;
		pvm_cpu_lease.mapped = true;
		smccc_set_retval(vcpu, SMCCC_RET_SUCCESS, PAGE_SIZE, 0, 0);
		hyp_spin_unlock(&pvm_dma_share_lock);
		return true;
	}
	if (!ret)
		WARN_ON(__pkvm_guest_return_page(pvm_cpu_lease.owner_vcpu,
						pvm_cpu_lease.owner_ipa, vm,
						receiver_ipa, pa));
	hyp_spin_unlock(&pvm_dma_share_lock);

invalid:
	smccc_set_retval(vcpu, SMCCC_RET_INVALID_PARAMETER, 0, 0, 0);
	return true;
}

static bool pvm_cpu_lease_return(struct pkvm_hyp_vcpu *hyp_vcpu)
{
	struct kvm_vcpu *vcpu = &hyp_vcpu->vcpu;
	u64 token = smccc_get_arg2(vcpu);
	int ret;

	hyp_spin_lock(&pvm_dma_share_lock);
	if (!pvm_cpu_lease.mapped || pvm_cpu_lease.token != token ||
	    pvm_cpu_lease.receiver != pkvm_hyp_vcpu_to_hyp_vm(hyp_vcpu) ||
	    pvm_cpu_lease.receiver_endpoint != hyp_vcpu_to_endpoint_id(hyp_vcpu))
		goto invalid_locked;
	ret = __pkvm_guest_return_page(pvm_cpu_lease.owner_vcpu,
					pvm_cpu_lease.owner_ipa, pvm_cpu_lease.receiver,
					pvm_cpu_lease.receiver_ipa, pvm_cpu_lease.pa);
	if (ret)
		goto invalid_locked;
	memset(&pvm_cpu_lease, 0, sizeof(pvm_cpu_lease));
	smccc_set_retval(vcpu, SMCCC_RET_SUCCESS, 0, 0, 0);
	hyp_spin_unlock(&pvm_dma_share_lock);
	return true;

invalid_locked:
	smccc_set_retval(vcpu, SMCCC_RET_INVALID_PARAMETER, 0, 0, 0);
	hyp_spin_unlock(&pvm_dma_share_lock);
	return true;
}

/* Owner-side revoke restores the page before invalidating the lease token. */
static bool pvm_cpu_lease_revoke(struct pkvm_hyp_vcpu *hyp_vcpu)
{
	struct kvm_vcpu *vcpu = &hyp_vcpu->vcpu;
	u64 token = smccc_get_arg2(vcpu);
	int ret = 0;

	hyp_spin_lock(&pvm_dma_share_lock);
	if (!pvm_cpu_lease.owner || pvm_cpu_lease.token != token ||
	    pvm_cpu_lease.owner != pkvm_hyp_vcpu_to_hyp_vm(hyp_vcpu) ||
	    pvm_cpu_lease.owner_vcpu != hyp_vcpu)
		goto invalid_locked;
	if (pvm_cpu_lease.mapped)
		ret = __pkvm_guest_return_page(pvm_cpu_lease.owner_vcpu,
					pvm_cpu_lease.owner_ipa,
					pvm_cpu_lease.receiver,
					pvm_cpu_lease.receiver_ipa,
					pvm_cpu_lease.pa);
	if (ret)
		goto invalid_locked;
	memset(&pvm_cpu_lease, 0, sizeof(pvm_cpu_lease));
	smccc_set_retval(vcpu, SMCCC_RET_SUCCESS, 0, 0, 0);
	hyp_spin_unlock(&pvm_dma_share_lock);
	return true;

invalid_locked:
	smccc_set_retval(vcpu, SMCCC_RET_INVALID_PARAMETER, 0, 0, 0);
	hyp_spin_unlock(&pvm_dma_share_lock);
	return true;
}

static bool pvm_cpu_lease_query(struct pkvm_hyp_vcpu *hyp_vcpu)
{
	struct kvm_vcpu *vcpu = &hyp_vcpu->vcpu;
	u64 token = smccc_get_arg2(vcpu);
	bool active, mapped;

	hyp_spin_lock(&pvm_dma_share_lock);
	active = pvm_cpu_lease.owner && pvm_cpu_lease.token == token &&
		((pvm_cpu_lease.owner_vcpu == hyp_vcpu) ||
		 (pvm_cpu_lease.receiver == pkvm_hyp_vcpu_to_hyp_vm(hyp_vcpu)));
	mapped = pvm_cpu_lease.mapped;
	hyp_spin_unlock(&pvm_dma_share_lock);
	if (!active)
		goto invalid;
	smccc_set_retval(vcpu, SMCCC_RET_SUCCESS, mapped, 0, 0);
	return true;

invalid:
	smccc_set_retval(vcpu, SMCCC_RET_INVALID_PARAMETER, 0, 0, 0);
	return true;
}

static bool pvm_cpu_lease_event_poll(struct pkvm_hyp_vcpu *hyp_vcpu)
{
	struct kvm_vcpu *vcpu = &hyp_vcpu->vcpu;
	struct pkvm_hyp_vm *vm = pkvm_hyp_vcpu_to_hyp_vm(hyp_vcpu);

	hyp_spin_lock(&pvm_dma_share_lock);
	if (!pvm_cpu_lease.owner || !pvm_cpu_lease.event_pending ||
	    pvm_cpu_lease.receiver != vm ||
	    pvm_cpu_lease.receiver_endpoint != hyp_vcpu_to_endpoint_id(hyp_vcpu))
		goto invalid_locked;

	pvm_cpu_lease.event_pending = false;
	smccc_set_retval(vcpu, SMCCC_RET_SUCCESS, pvm_cpu_lease.token,
			 PAGE_SIZE, 0);
	__kvm_inject_el1_irq_live(vcpu);
	hyp_spin_unlock(&pvm_dma_share_lock);
	return true;

invalid_locked:
	smccc_set_retval(vcpu, SMCCC_RET_INVALID_PARAMETER, 0, 0, 0);
	hyp_spin_unlock(&pvm_dma_share_lock);
	return true;
}

static bool pvm_cpu_lease_id_get(struct pkvm_hyp_vcpu *hyp_vcpu)
{
	struct kvm_vcpu *vcpu = &hyp_vcpu->vcpu;
	u32 endpoint_id = hyp_vcpu_to_endpoint_id(hyp_vcpu);

	if (!endpoint_id) {
		smccc_set_retval(vcpu, SMCCC_RET_INVALID_PARAMETER, 0, 0, 0);
		return true;
	}
	smccc_set_retval(vcpu, SMCCC_RET_SUCCESS, endpoint_id, 0, 0);
	return true;
}

bool pkvm_pvm_dma_share_hvc(struct pkvm_hyp_vcpu *hyp_vcpu,
			    u64 *exit_code)
{
	struct kvm_vcpu *vcpu = &hyp_vcpu->vcpu;

	switch (smccc_get_arg1(vcpu)) {
	case KVM_PVM_DMA_SHARE_GRANT:
		return pvm_dma_share_grant(hyp_vcpu, exit_code);
	case KVM_PVM_DMA_SHARE_ACCEPT:
		return pvm_dma_share_accept(hyp_vcpu, exit_code);
	case KVM_PVM_DMA_SHARE_QUERY:
		return pvm_dma_share_query(hyp_vcpu);
	case KVM_PVM_DMA_SHARE_EXPORT:
		return pvm_cpu_lease_export(hyp_vcpu, exit_code);
	case KVM_PVM_DMA_SHARE_IMPORT:
		return pvm_cpu_lease_import(hyp_vcpu, exit_code);
	case KVM_PVM_DMA_SHARE_RETURN:
		return pvm_cpu_lease_return(hyp_vcpu);
	case KVM_PVM_DMA_SHARE_REVOKE:
		return pvm_cpu_lease_revoke(hyp_vcpu);
	case KVM_PVM_DMA_SHARE_LEASE_QUERY:
		return pvm_cpu_lease_query(hyp_vcpu);
	case KVM_PVM_DMA_SHARE_EVENT_POLL:
		return pvm_cpu_lease_event_poll(hyp_vcpu);
	case KVM_PVM_DMA_SHARE_ID_GET:
		return pvm_cpu_lease_id_get(hyp_vcpu);
	case KVM_PVM_MSG_SEND_BEGIN:
		return pvm_msg_send_begin(hyp_vcpu);
	case KVM_PVM_MSG_SEND_CHUNK:
		return pvm_msg_send_chunk(hyp_vcpu);
	case KVM_PVM_MSG_SEND_COMMIT:
		return pvm_msg_send_commit(hyp_vcpu);
	case KVM_PVM_MSG_RECV_INFO:
		return pvm_msg_recv_info(hyp_vcpu);
	case KVM_PVM_MSG_RECV_CHUNK:
		return pvm_msg_recv_chunk(hyp_vcpu);
	case KVM_PVM_MSG_RECV_POP:
		return pvm_msg_recv_pop(hyp_vcpu);
	case KVM_PVM_MSG_QUEUE_DEPTH:
		return pvm_msg_queue_depth(hyp_vcpu);
	default:
		smccc_set_retval(vcpu, SMCCC_RET_INVALID_PARAMETER, 0, 0, 0);
		return true;
	}
}

void pkvm_pvm_dma_share_teardown(struct pkvm_hyp_vm *vm)
{
	hyp_spin_lock(&pvm_dma_share_lock);
	__pvm_cpu_lease_revoke(vm);
	if (pvm_dma_share.owner == vm || pvm_dma_share.receiver == vm)
		__pvm_dma_share_revoke();
	memset(pvm_msg_queues, 0, sizeof(pvm_msg_queues));
	memset(pvm_msg_staging, 0, sizeof(pvm_msg_staging));
	hyp_spin_unlock(&pvm_dma_share_lock);
}
