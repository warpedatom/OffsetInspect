# Threat provider interface

This document defines the contract every threat provider must satisfy so that
`Invoke-OIPrefixBoundarySearch` can drive it, and scopes the work required to
add new providers or to parallelise prefix probing safely.

Place this file under `docs/` in the repository.

## 1. The scanner contract

The boundary search is provider-agnostic. It receives a single **scanner
callback** — a `[scriptblock]` invoked positionally with one argument:

```powershell
& $scanner <prefixLength>   # [int64] number of units in the prefix to test
```

"Unit" is bytes for `RawBytes` mode and Unicode scalars for AMSI `Text` mode.
The search never interprets units itself; it only bisects the range `0..UnitCount`.

The callback MUST return a single object exposing at least:

| Property         | Type     | Meaning                                                        |
| ---------------- | -------- | -------------------------------------------------------------- |
| `Status`         | string   | One of the status tokens in section 2. Required.               |
| `ProviderResult` | int/null | Raw provider code (AMSI result, Defender exit code, etc.).      |
| `HResult`        | str/null | Provider HRESULT where applicable.                             |
| `SignatureName`  | str/null | Detected signature/threat name when the provider reports one.  |
| `Message`        | str/null | Human-readable diagnostic for non-definitive states.           |
| `RawOutput`      | str/null | Verbatim provider output, surfaced only with -IncludeProviderOutput. |

A `$null` return, or a null/whitespace `Status`, is normalised to `Status = 'Error'`
by the search. Exceptions thrown by the callback are caught and converted to
`Status = 'Error'` with the exception message — a provider crash never aborts the
search, it fails it cleanly.

## 2. Status tokens

`Threat.Search.ps1` classifies every status into exactly one of three buckets:

- **Negative** (`Clean`, `NotDetected`) — the prefix is not detected.
- **Positive** (`Detected`, `Blocked`) — the prefix is detected.
- **Non-definitive** (anything else: `Indeterminate`, `Timeout`, `Error`, ...) —
  the provider could not give a trustworthy answer.

Rules the search enforces:

1. **Empty-prefix baseline.** A length-0 scan must classify as Negative. If a
   provider cannot, the search aborts with a clear error rather than guessing.
2. **Monotonic transition assumption.** The search assumes a single
   clean-to-detected transition. It does not detect multiple transitions or
   context-sensitive detections; those surface as instability or as a boundary
   that manual validation must confirm. This assumption is documented to the
   operator in the result `Warnings`.
3. **Non-definitive is fatal, not silent.** A single non-definitive status at a
   probed midpoint or at either boundary re-check fails the search
   (`Success = $false`, `Confidence = 'None'`). The search never rounds an
   ambiguous provider answer to clean or detected.
4. **Stability is re-verified.** Both sides of the final boundary are re-scanned
   `RepeatCount` times. `Stable`/`Confidence` reflect only what the provider
   actually reproduced.

## 3. Adding a new provider

A new engine (for example ClamAV on Linux, or a cloud reputation lookup) is added
**without touching `Invoke-OIPrefixBoundarySearch`**. The steps:

1. Create `Private/Threat.<Name>.ps1` with:
   - a metadata function (`Get-OI<Name>ProviderMetadata`) returning an object of
     provenance/versioning fields, and
   - a scan function that maps the provider's native result to the section-1
     object shape and the section-2 status tokens.
2. In `Invoke-OffsetThreatScan`, add the engine to the `-Engine` `ValidateSet`,
   its selection rule in the `Auto` block, and build a `$scanner` closure that
   calls your scan function for a given prefix length (mirroring the existing
   AMSI and Defender closures). Return the section-1 object for `PrefixLength -eq 0`
   as a synthetic Negative baseline, exactly as the shipped providers do.
3. Add provider metadata to `docs/PROVENANCE.md`.

The search, output contracts, probe log, and boundary semantics all work
unchanged because they only depend on the section-1/section-2 contract.

## 4. Parallelising prefix probing (not yet safe)

The cache is now a `ConcurrentDictionary`, so the *memoisation* layer is
parallel-ready. The probing itself is **not**, because the shipped scanner
closures share mutable, single-threaded state:

| Provider  | Shared mutable state                                   | Why it blocks parallelism                                             |
| --------- | ------------------------------------------------------ | -------------------------------------------------------------------- |
| AMSI Text/RawBytes | one `AmsiSession` instance                    | A single session is driven serially; concurrent scans on one session are not a supported contract. |
| Defender  | one source `FileStream` position + one copy buffer + one temp file path | `Copy-OIStreamPrefix` seeks the shared stream and writes a shared buffer/file; concurrent workers would corrupt each other's prefix. |

To make probing parallel-safe (a genuine future feature, not a drop-in), each
worker needs isolated resources before any `ForEach-Object -Parallel` is added:

- **AMSI RawBytes** is the closest: it already scans an immutable in-memory
  `byte[]`. Give each worker its own `AmsiSession` and it parallelises cleanly.
- **AMSI Text** additionally shares the decoded string and scalar map, both of
  which are immutable — again, per-worker sessions are the only requirement.
- **Defender** needs per-worker independent read streams (or a single preloaded
  immutable buffer), per-worker copy buffers, and per-worker temp files.

Until those are in place, keep probing sequential. The concurrent cache costs
nothing today and removes one landmine from that future work.

## 5. What the audit probe log guarantees

Every distinct provider invocation (cache miss) appends one record to `ProbeLog`
with `Sequence`, `PrefixLength`, `Status`, `ProviderResult`, `SignatureName`,
`Cacheable`, `ElapsedMs`, and `TimestampUtc`. Cache hits are not re-logged, so
`ProbeLog.Count` is the true provider cost of a scan — suitable for attaching a
full boundary-search transcript to an engagement report. The same records stream
to `-Verbose` in real time.
