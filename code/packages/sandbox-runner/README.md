# Sandbox Runner

The Sandbox Runner is the only component allowed to create dynamic execution
containers. Callers submit versioned structured requests; they cannot provide a
shell command, Docker flags, host paths, or an unregistered image.
