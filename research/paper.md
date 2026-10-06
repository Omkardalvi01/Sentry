# Sentry: Reproducible Hybrid Verification of REST API Inventory Discrepancies

Manuscript draft. Author details and venue formatting must be supplied before submission. Results below are measured on the included controlled fixtures, not production deployments.

## Abstract

Undocumented routes and accessible deprecated operations can create API inventory discrepancies, but successful HTTP responses alone provide weak evidence. Wildcard handlers, login redirects, public documentation, and generic responses complicate automated detection. We present Sentry, a hybrid system that combines OpenAPI inventory context, passively observed traffic, and active verification. The method distinguishes reachability from response identity and authentication exposure, and reports confidence independently of severity. A reproducible evaluation on three local HTTP testbeds across five traffic seeds compares component baselines and ablations. Mean endpoint F1 is 0.923 for the hybrid method, 0.833 for active scanning alone, and 0.706 for passive inventory comparison. These results support passive-to-active verification within the controlled scenarios. Behavioral experiments show that robust endpoint-relative size checks detect the injected payload anomalies, while Isolation Forest and graph-enriched features provide no demonstrated improvement in this benchmark. Entire-application holdout exposes failed generalization. We release the experiment protocol and raw-artifact generator, and bound all claims to the evaluated fixtures.

## 1. Introduction

API inventory management includes knowing which versions and endpoints exist and which remain supported. OWASP API9 identifies obsolete documentation and unmaintained versions as relevant security risks [1]. A documented deprecated operation is not necessarily an overdue retirement, and an undocumented response is not necessarily exploitable. Automated tooling should preserve those distinctions.

Sentry investigates whether complementary evidence sources improve detection of actionable inventory discrepancies. Its contribution is an inspectable fusion and verification method and a reproducible evaluation artifact. We do not claim that API graphs, passive discovery, or machine-learning anomaly detection are new techniques.

The research questions are: RQ1, does passive discovery followed by active verification improve endpoint detection over either source alone? RQ2, which verification components reduce false positives? RQ3, do inventory features or Isolation Forest add behavioral detection value under this experimental design?

## 2. Related work

ZAP imports API definitions and actively scans their URLs [2]. Its general vulnerability alerts differ from Sentry's inventory findings, so total alert counts are not directly comparable. RESTler uses dependency-aware stateful API fuzzing to exercise cloud services [3]; Sentry does not implement stateful fuzzing or infer service-call dependencies. APISENSOR studies API discovery from runtime traffic logs using normalization and graph-based clustering [4]. Sentry's narrower question is how observed discrepancies can be actively verified using a supplied inventory. Isolation Forest is an established outlier-detection method; its scores and threshold behavior are described by scikit-learn [5]. The combination used here must be assessed empirically rather than assumed beneficial.

## 3. Method

### 3.1 Inventory representation

Specifications are parsed into a Memgraph inventory with spec, server, path, operation, tag, and security relationships. Operation identity includes spec title, version, method, and route template. Literal paths precede parameter templates during matching. Effective operation security includes inherited root requirements and explicitly public alternatives. Traffic without unambiguous inventory scope retains unknown context.

The graph supplies inventory context only. No downstream service-call edges are inferred and no blast-radius score is reported. A graph database is an implementation choice, not a demonstrated algorithmic advantage over an equivalent indexed inventory representation.

### 3.2 Passive-to-active verification

Observed undocumented operations become candidates. The active planner combines these with deprecated-operation probes, alternate-version probes, method probes, and a fixed shadow-path list. The full method therefore reaches routes that a fixed path list misses. It does not claim to discover endpoints absent from both traffic and the probe plan.

Three nonexistent-route responses are collected per directory, method, and authentication context. Responses are compared using status, media type, and normalized content. Dynamic request and trace identifiers are normalized. Equal response lengths alone do not establish equivalence.

Response validation keeps a bounded body separate from its display snippet. Outcomes distinguish matching, mismatching, unavailable, and truncated schemas. A schema mismatch lowers verification confidence; missing schemas supply no schema-agreement evidence. Retirement keywords alone cannot suppress findings.

Protected deprecated operations with supplied credentials are retested without those credentials. A finding requires equivalent successful content and a specification expectation of authentication. Reachability and schema agreement alone never establish critical impact.

### 3.3 Behavioral detection

The detector uses endpoint-relative log body lengths, status, missing-value indicators, and cyclic time when baseline history covers at least a day. Inventory features include context availability, documented membership, deprecation, and effective authentication requirements. Isolation Forest is trained on approved baseline events. A later validation window calibrates a 1% target false-positive threshold.

A robust numerical component compares body-size deviations against median-based endpoint profiles with a minimum scale. Its threshold is calibrated separately. Model outputs expose raw scores and reasons, without treating scores as probabilities. Every traffic event is evaluated; a normal endpoint cannot bypass later analysis through a cached verdict.

### 3.4 Implementation and reproducibility

Go handles specification parsing, active scanning, Kafka consumption, and the dashboard API. Python handles model training and inference. SQLite stores traffic, predictions, scan history, and model metadata. Kafka offsets commit after durable handling; detector failures remain pending for replay. Redis optionally caches inventory snapshots, not prediction results.

The scanner's spec-file experiment mode uses the production planner and verifier. Models record feature version, parameters, seed, threshold, window bounds, and a training-data digest. Dependencies have pinned versions and hashes. Reproduction commands and the exact evaluated binary digest are included in the artifact.

## 4. Experimental design

Three resettable HTTP testbeds represent a resource API, a versioned API, and a gateway with catch-all handling. Their shared scenario structure includes documented new observations, large valid responses, accessible deprecated operations, undocumented routes, alternate versions, redirects, retired operations, generic schema mismatches, errors, public operations, and missing authentication.

Each application and seed supplies 320 actual requests to its local fixture: 160 historical training events, 40 later validation events, and 120 test events. Five seeds yield 4,800 collected traffic events. Labels are stored separately and do not enter model features. Spec membership is prior inventory knowledge, not a label injected from evaluation outcomes.

Endpoint evaluation counts actionable inventory/lifecycle discrepancies, retaining authentication evidence separately. Behavioral evaluation uses only injected behavioral labels, preventing inventory alerts from inflating anomaly metrics. The status-based comparator applies a status rule to observed test operations; it is a decision baseline, not an equivalent discovery implementation or request-cost baseline.

Active variants share a 250-request ceiling, five workers, and a 1,000 requests/second rate limit. Their actual request counts differ and remain reported; budget is not padded with dummy requests.

Ablations remove schema checks, catch-all suppression, passive candidates, inventory features, or ML. Leave-one-application-out experiments fit and calibrate models exclusively on the other two applications. Endpoint precision, recall, F1, false positives, request overhead, and scan duration are recorded. Event evaluation includes PR-AUC and local inference latency. Confidence intervals bootstrap application/seed F1 values with 2,000 resamples; shared fixture structure limits their interpretation.

## 5. Results

### 5.1 Inventory discrepancies

| Method | Mean endpoint F1 |
|---|---:|
| active only | 0.833 |
| hybrid | 0.923 |
| passive inventory | 0.706 |
| status based | 0.838 |
| without catch all | 0.679 |
| without passive | 0.833 |
| without schema | 0.857 |

Passive-to-active verification improves recall by reaching an undocumented export route outside the fixed probe list. Schema inspection reduces confirmed false positives from a generic response on a deprecated route. Catch-all suppression is especially important for the gateway fixture: removing it causes many ordinary nonexistent routes to become successful-looking findings.

The hybrid still flags intentionally available API documentation that is absent from the supplied spec. This remains a false positive under the actionable-discrepancy truth definition and explains why the reported F1 is below one. The example demonstrates that distinct reachability is weaker than intended exposure policy.

### 5.2 Behavioral anomalies

| Method | Mean event F1 |
|---|---:|
| held out inventory behavior | 0.000 |
| held out traffic behavior | 0.000 |
| inventory behavior | 1.000 |
| inventory if only | 0.000 |
| traffic behavior | 1.000 |
| traffic if only | 0.000 |
| without ml | 1.000 |

The combined detector and numerical-only ablation identify the deliberately extreme in-application payload anomalies. Isolation Forest alone fails to improve detection, and inventory features do not improve behavioral F1. Entire-application holdout fails: scoped endpoint profiles are unavailable for the held-out application, and the global learned distribution does not generalize adequately.

These findings do not support a claim of superior graph-aware machine learning. They support retaining the numerical baseline and treating the ML component as experimental. The current behavior fixtures are insufficiently diverse to establish robust superiority of either approach.

## 6. Threats to validity

The applications share routes and implementation logic; they are controlled scenario variations, not independent production systems. Seed repetition mainly changes ordinary response sizes and traffic choices. Endpoint F1 therefore has little seed variation, and degenerate bootstrap intervals should not be mistaken for certainty about real-world performance.

Payload anomalies are extreme. Apparent perfect within-application behavior detection may overestimate utility on subtle attacks. The benchmark does not establish exploit detection, production coverage, resilience to adversarial baseline poisoning, or downstream service impact. A stale specification can misclassify legitimate undocumented or public endpoints.

Schema mismatch does not prove that a live endpoint is retired; the benchmark's negative mismatch fixture uses external truth. Excluding low-confidence candidates from confirmed metrics reflects an explicit operating point, and those candidates remain in the artifact. Unsupported recursive schemas are unavailable rather than verified.

Scan duration approximates a batch verification delay. Inference latency and Python-process peak memory do not represent end-to-end Kafka service latency or isolated service memory. External ZAP comparison is supplementary and has not been included in these reported tables.

## 7. Conclusion

Sentry provides a reproducible method for verifying API inventory discrepancies using specifications, passive observations, and active requests. The controlled evaluation supports passive-to-active fusion and catch-all suppression. It also exposes a remaining documentation false positive and failed behavioral generalization. Independent applications and realistic authorized traces are required before extending these conclusions beyond the released fixtures.

## References

1. OWASP. API9:2023 Improper Inventory Management. https://api-security.owasp.org/editions/2023/en/0xa9-improper-inventory-management/
2. ZAP. API Scan documentation. https://www.zaproxy.org/docs/docker/api-scan/
3. Atlidakis, V., Godefroid, P., and Polishchuk, M. RESTler: Stateful REST API Fuzzing. ICSE 2019. https://www.microsoft.com/en-us/research/uploads/prod/2021/03/RESTler.pdf
4. APISENSOR: Robust Discovery of Web API from Runtime Traffic Logs. arXiv:2603.23852. https://arxiv.org/abs/2603.23852
5. scikit-learn. IsolationForest documentation. https://scikit-learn.org/stable/modules/generated/sklearn.ensemble.IsolationForest.html
