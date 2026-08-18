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

static bool pvm_dma_share_has_request(struct kvm_vcpu *vcpu)
{
	return vcpu->arch.hyp_reqs->type != KVM_HYP_LAST_REQ;
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
	default:
		smccc_set_retval(vcpu, SMCCC_RET_INVALID_PARAMETER, 0, 0, 0);
		return true;
	}
}

void pkvm_pvm_dma_share_teardown(struct pkvm_hyp_vm *vm)
{
	hyp_spin_lock(&pvm_dma_share_lock);
	if (pvm_dma_share.owner == vm || pvm_dma_share.receiver == vm)
		__pvm_dma_share_revoke();
	hyp_spin_unlock(&pvm_dma_share_lock);
}
