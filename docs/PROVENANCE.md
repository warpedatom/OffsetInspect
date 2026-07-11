# Threat-scanning provenance

OffsetInspect 2.0 includes an independently implemented detection-boundary subsystem. The design is informed by the general prefix-search technique used by public defensive tools such as [ThreatCheck](https://github.com/rasta-mouse/ThreatCheck), but OffsetInspect does not bundle or compile ThreatCheck source, binaries, build output, or project state.

## Implementation boundaries

- AMSI integration is implemented directly against the documented Windows AMSI API.
- Microsoft Defender integration invokes the locally installed `MpCmdRun.exe` through a provider adapter.
- Prefix search, status normalization, repeatability checks, source mapping, output schemas, tests, and packaging are OffsetInspect-native code.
- The Gallery package contains no third-party executable or compiled dependency.

This distinction keeps the module auditable, avoids inheriting unrelated artifacts, and allows provider failures to use the same explicit error model as the rest of OffsetInspect.

## Attribution

ThreatCheck is acknowledged as prior art for defensive content-prefix analysis. Consult its repository for its authorship and license. No claim is made that an OffsetInspect boundary is identical to a ThreatCheck result because the provider adapters, normalization rules, scan modes, and validation behavior differ.
