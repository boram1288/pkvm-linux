# pkvm-linux

이 브랜치는 Linux `v6.18.21` stable 위에 pKVM 및 프로젝트 패치를 rebase한 작업 브랜치입니다.

## 기준

- 기준 태그: `v6.18.21` (`44c944a679974c2d18ee9b87070456d34193f3d4`)
- 작업 브랜치: `pkvm-6.18.21-rebased-20261007`
- 기존 `v6.18` 위의 원본 733개 패치를 재적용했다. 이미 stable에 포함된
  S1POE/ID register 수정 두 개를 제외한 731개가 원래 순서로 적용되었다.
- 원본 패치의 author, author date, commit message를 보존했다.
- `v6.18.21..HEAD`에는 merge commit이 없다.
- README를 제외한 전체 소스는 22개 QEMU 회귀 시험을 통과한 기존 병합 커밋
  `e99f17000d31`과 byte-for-byte 동일하다.
- PSCI reset의 pending exception/PC update 제거는 Host와 EL2가 공유하는
  `kvm_reset_vcpu_psci()`에 적용했다. 기존 ID register 초기화와 protected
  sysreg reset 경로를 유지했다.

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

최초 `pkvm-6.18-full` 통합 당시 README 문서화 커밋을 제외한
`v6.18..pkvm-6.18-full` 기준 pKVM 패치 규모는 다음과 같습니다.

- 커밋 수: 721개
- 변경 파일 수: 237개
- 추가 라인 수: 34,178줄
- 삭제 라인 수: 3,506줄

주요 변경은 `arch/arm64/kvm`, `arch/arm64/kvm/hyp/nvhe`, `drivers/iommu`,
`drivers/vfio`, `drivers/virt/coco/pkvm-guest`, `drivers/misc/pkvm-smc`에 집중되어 있습니다.
