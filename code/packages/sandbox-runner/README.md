# Sandbox Runner

The Sandbox Runner is the only component allowed to create dynamic execution
containers. Callers submit versioned structured requests; they cannot provide a
shell command, Docker flags, host paths, or an unregistered image.

The Docker runtime mounts `/output` from a size-limited tmpfs volume. A second,
read-only container using the same digest-pinned tool image keeps that volume
mounted while outputs are copied after the tool exits. Registered Linux tool
images must therefore provide `/bin/sleep`; callers cannot override the keeper
entrypoint or arguments.

`ResourceBudget.cpu_millis` is a capacity limit in millicores (`1000` is one
logical CPU). `SandboxResourceUsage.cpu_millis` is accumulated CPU time in
milliseconds, integrated from Docker's execution-time CPU samples.
