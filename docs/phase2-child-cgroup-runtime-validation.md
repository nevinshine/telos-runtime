# Phase 2.3.2 Child Cgroup Runtime Validation

Date: 2026-11-05

## Environment and scope

Validation was performed in the privileged Fedora 45 testing VM. The
diagnostic experiment used the existing test-only BPF object and C helper; no
production LSM code, production map layout, or production loader behavior was
changed.

The toolchain used the repository's Clang BPF build, C compiler, and
`pkg-config`/libbpf development package. Exact kernel, compiler, libbpf, and
distribution package version strings were not captured in the recorded
results and are intentionally not inferred here.

## Build and load results

The following test-only components compiled successfully:

- `tests/kernel/bpf/child_cgroup_fork_probe.bpf.c`
- `tests/kernel/bpf/child_task_cgroup_probe.bpf.c`
- `tests/kernel/child_cgroup/clone_into_cgroup.c`

The child-task probe object loaded successfully, and both typed tracepoint
programs attached successfully:

- `tp_btf/task_newtask`
- `tp_btf/sched_process_fork`

The libbpf runner created the `events` ring-buffer consumer and collected
events successfully.

## Observed events

### Ordinary fork control

| Field | Value |
|---|---:|
| Parent TGID | 3705 |
| Child TGID | 3706 |
| Current cgroup ID | 7294 |
| Child cgroup ID | 7294 |

The parent execution-context cgroup ID and the child task-derived cgroup ID
matched for ordinary fork.

### `CLONE_INTO_CGROUP`

| Field | Value |
|---|---:|
| Parent TGID | 3717 |
| Child TGID | 3718 |
| Current cgroup ID | 7294 |
| Child cgroup ID | 7314 |

The parent execution-context cgroup ID remained `7294`, while the
child-task-derived cgroup ID was `7314`, matching the cgroup targeted by
`CLONE_INTO_CGROUP`.

## Interpretation

These results validate that a typed child-task tracepoint can observe the
actual child cgroup independently of the current-task helper. In the
`CLONE_INTO_CGROUP` case, the two values differ exactly as expected: the
current-task helper reports the parent's cgroup, while the CO-RE child-task
observation reports the child's destination cgroup.

This establishes the diagnostic mechanism for direct child-task cgroup
identity observation on the tested Fedora 45 kernel. It also demonstrates why
copying `bpf_get_current_cgroup_id()` from `sched_process_fork` into a
child-PID record is insufficient for children created directly in another
cgroup.

## Evidence boundary

This validates only the test-only diagnostic BPF probe, its typed tracepoint
attachments, and ring-buffer event delivery. It does **not** validate:

- production Telos LSM program loading or attachment;
- production process-map updates;
- production identity enforcement decisions;
- first-operation authorization for a child;
- taint propagation or cleanup behavior.

No production enforcement guarantee is claimed.

## Remaining work

1. Test kernel-version and BTF compatibility across all supported kernels.
2. Verify lifecycle, PID reuse, cgroup deletion, migration, and cleanup
   correctness.
3. Define and test thread-versus-process identity semantics, including TGID
   and task-level behavior.
4. Integrate the validated child-task observation into production LSM
   identity handling without weakening fail-closed behavior.
5. Perform production LSM integration and adversarial testing in the
   isolated VM.
