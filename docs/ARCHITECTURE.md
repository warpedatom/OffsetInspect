# Architecture

## Design goals

OffsetInspect 2.0 is organized around four constraints:

1. File size should not be multiplied by offset count.
2. Module installation must be independent of repository layout.
3. Provider failures must remain distinct from detections.
4. Human-readable output and automation output must derive from the same structured objects.

## Module loading

`OffsetInspect.psm1` dot-sources private implementation files followed by public commands. The Gallery folder contains every runtime dependency. Repository-root scripts are only CLI adapters and are not required after module installation.

## Inspection pipeline

`Invoke-OffsetInspect`:

1. Builds a deterministic file/offset plan.
2. Opens the optional comparison file once.
3. Groups requests by source file.
4. Opens each unique source file once with a read-only sharing policy so line mapping and byte windows use a consistent file image.
5. Parses and validates all offsets.
6. Streams the file once to map only requested offsets and their bounded context lines.
7. Reads target bytes and byte windows on demand.
8. Decodes bounded line previews using the resolved encoding.
9. Creates `OffsetInspect.Result` objects.
10. Renders those objects as human, object, JSON, or CSV output.

## Bounded source mapping

The source mapper does not retain a complete line-start index. Encoding detection, line mapping, and range reads share the same open file stream. It maintains:

- A queue containing at most `ContextLines` completed lines.
- One record per unique requested offset.
- A current-line list and a pending-context list, so completed records are not revisited for every later line.
- Future-line descriptors only until each record has enough context.

The stream can stop early once every requested offset has a target line and sufficient following context.

## Threat providers

Threat providers normalize their responses before the binary-search component consumes them. The search component therefore has no engine-specific assumptions beyond positive, negative, and non-definitive states.

The nested offset inspection is performed only after a stable candidate boundary exists.

## Output stability

Object properties are explicitly created in a stable order. JSON mode uses an explicit input array to avoid the single-object shape change normally produced by `ConvertTo-Json`. CSV mode uses a deliberately flattened schema and joins warning arrays with semicolons.
