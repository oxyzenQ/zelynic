# I-6 — eBPF Program Skeleton, Compile-Only

**Branch**: intergalaxion (experimental)
**Base**: stable v3.1.0 on main
**Status**: source-only, compile-only, no live kernel operations

## Purpose

I-6 introduces the eBPF program skeleton shape only. No programs are
loaded, attached, or created. No userspace loader exists. This phase
defines the *skeleton layout* for future observer programs.

## Safety guarantees

* I-6 is experimental branch only.
* main remains stable v3.1.0.
* I-6 introduces eBPF program skeleton shape only.
* source-only / compile-only.
* no userspace loader.
* no eBPF attach.
* no eBPF program load.
* no eBPF map create.
* no ring buffer open.
* no live kernel event read.
* no map pin.
* no packet drop.
* no enforcement.
* no block/allow/quota.
* no nft/tc fallback.
* no public CLI.
* no kernel mutation.
* no ledger file write.
* no persistence.
* existing v3.1 usage JSON schema unchanged.
* existing v3.1 ledger JSON schema unchanged.
* I-5 readiness gate remains model-only.

## Models added

* EbpfProgramSkeletonKind (SocketFilterObserver / CgroupSkbObserver /
  TracepointObserver)
* EbpfProgramSkeletonStatus (SourceOnly / CompilePlanned / CompileReady /
  KernelLoadUnsupported)
* EbpfProgramSkeleton
* EbpfProgramSkeletonSet

## Behavior

Skeletons describe the intended shape of future observer programs. All
operation flags default to false and must remain false. Validation
rejects any skeleton or set that enables live operations.

## Next phase

I-7 — Loader Boundary, Disabled by Default.
