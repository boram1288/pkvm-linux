# pkvm-linux

이 브랜치는 Linux `v6.18`을 기준으로 pKVM 관련 패치를 통합한 작업 브랜치입니다.

## 기준

- 기준 태그: `v6.18`
- 작업 브랜치: `pkvm-6.18-full`
- 원격 추적 브랜치: `github/pkvm-6.18-full`

## 주요 반영 내용

- arm64 KVM/pKVM 코어 확장
  - protected guest, host stage-2, hyp request, 메모리 소유권 전환 경로 보강
  - pKVM hyp 모듈 로딩, hyp trace/event, ftrace 지원 추가

- pKVM IOMMU 및 VFIO 연동
  - arm-smmu-v3 기반 pKVM IOMMU, pVIOMMU, nested/PV SMMU 경로 추가
  - VFIO device assignment, non-coherent device, low power feature 경로 보강

- pKVM 디바이스/전원 관리
  - pKVM guest/device power 요청 HVC와 관련 PM 드라이버 추가
  - virtio balloon, pkvm guest, device resource 처리 경로 보강

- pKVM SMC 필터
  - `drivers/misc/pkvm-smc` 드라이버 추가
  - SMC allow list, denied SMC trace, permissive 옵션 지원

- 문서와 테스트
  - `Documentation/virt/kvm/arm/` 아래 pKVM, pKVM IOMMU, pVIOMMU, MMIO guard 문서 추가
  - KVM/pKVM 및 hyp trace selftest 추가

## 참고

`v6.18..pkvm-6.18-full` 기준으로 237개 파일에 pKVM 관련 변경이 포함되어 있으며,
주요 변경은 `arch/arm64/kvm`, `arch/arm64/kvm/hyp/nvhe`, `drivers/iommu`,
`drivers/vfio`, `drivers/virt/coco/pkvm-guest`, `drivers/misc/pkvm-smc`에 집중되어 있습니다.
