# Implementation decisions

## Inventory and evidence

Operation identity is the JSON tuple `[spec title, spec version, method, route template]`. Literal route matches precede parameter matches. The same template in different specs is never sufficient to resolve an event without scope. Operation-level security overrides root security; an empty OR alternative permits anonymous access.

Graph ingestion replaces a scoped snapshot transactionally. Legacy root relationships are disconnected; existing scan/finding records remain. Reingesting a legacy inventory is required to populate the new scoped properties. Orphan legacy nodes can be removed later through an explicit maintenance operation; ingestion does not wipe the database.

The decision table is implemented in the production scanner and used unchanged by `scan-spec`:

| Evidence | Classification |
|---|---|
| Known operation, first traffic observation | New observation, not a shadow API |
| Observed operation absent from selected spec | Shadow candidate requiring verification |
| Deprecated operation with distinct 2xx response | Lifecycle discrepancy |
| Alternate version with distinct 2xx response | Inventory review |
| Undocumented non-HEAD/non-OPTIONS method with distinct 2xx response | Method discrepancy |
| Protected operation, supplied credentials, equivalent credential-free 2xx content | Authentication exposure |
| Redirect, 401/403, ordinary error, or matching catch-all | No confirmed active finding |
| Schema mismatch or truncated body | Low-confidence candidate, not verified response identity |

Missing schemas do not establish response identity. The scanner can still report distinct reachability with medium confidence. Neither a retirement keyword nor response length suppresses a finding on its own. There is no inferred retirement deadline.

## Durability and model lifecycle

SQLite uses WAL, foreign keys, a busy timeout, and one Go connection. Both languages execute the shared SQL schema and additive legacy migrations. Scan IDs are generated once and used throughout the API, database, and graph. A dashboard restart marks interrupted running jobs cancelled. Transport failures produce a partial scan with an explicit request-error count, preserving findings already collected.

Kafka commits follow durable event/prediction handling. An unavailable detector leaves a pending outcome; a durable reject permits committing malformed events. Failures to persist or commit stop the consumer instead of clearing an uncommitted batch. Pending replay is bounded to five events per retry cycle. Predictions are never cached by endpoint.

Model training uses approved historical windows. Calibration is separate and chronological; identical timestamp groups remain together. Retraining and rollback are serialized. Version records include feature version, digest, seed, parameters, baseline profiles, window bounds, and calibration results. Cold starts run deterministic inventory rules. Model loading rejects incompatible historical feature formats.

## Compatibility and limitations

Existing report fields and CLI strategy names remain available. Reports add confidence and evidence state. Mutating probes now require explicit opt-in. Retraining returns its activation outcome instead of promising background success. Endpoint-level prediction caching and invented blast radius were removed.

The current fixture benchmarks measure controlled local scenarios. Their three applications share substantial structure, and repeated seeds are not independent real deployments. The graph supplies inventory context, not inferred service calls. Unsupported recursive schemas are marked unavailable. Payload generation covers examples/defaults and basic required types; arbitrary constraints and stateful workflows may require fixtures. A protected operation returning identical public content can still reflect a stale spec; authentication findings therefore remain evidence-based exposure reports requiring review.
