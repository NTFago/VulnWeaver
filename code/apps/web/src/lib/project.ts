import type { Artifact, ArtifactKind } from "@vulnweaver/contracts";

const sampleKinds = new Set<ArtifactKind>(["source_archive", "source_repository", "elf", "pe"]);

/** Reports and analysis outputs cannot be submitted as task inputs. */
export function sampleArtifacts(artifacts: Artifact[]): Artifact[] {
  return artifacts.filter(artifact => sampleKinds.has(artifact.kind));
}
