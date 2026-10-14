# D06 — enforced outbound boundary and emergency stop: decision pack

**Decision pack. Nothing here is a decision.** D06 belongs to the security and
platform leads. This pack prepares its five required evidence elements, and it
reports one measured constraint that narrows the mechanism choice more than the
documents do on their own.

| | |
|---|---|
| Decision | Design the enforced outbound boundary and emergency stop (Integrated Baseline v1.6, Appendix E.3, D06) |
| Accountable role | Security and platform leads |
| Required evidence | "Data-flow/threat model, fail-closed decisions, worker escape tests, request limits and profile approval" |
| Also unconfirmed | Spec's own Phase 0 list includes confirming "the egress enforcement mechanism" — see §4 |
| Blocks | F05, which "precedes any scanner traffic"; then F06; and the activation of every proposed request ceiling |
| Drafted | 2026-10-14, by Claude Opus 5 at the owner's instruction |
| Status | **Unconfirmed / Blocked. §12's decision record is unsigned.** |

## 1. The decision as the documents state it

**The boundary must sit outside the worker.** Spec §4: "Enforce an allowlisted egress
route so a compromised worker cannot bypass application checks", and §3: "Grant
validation belongs at the egress boundary as well as the worker." The threat model's
central assumption is that the worker is fully compromised (`THREAT_MODEL.md` §2), so
anything the worker could choose not to do is not a control.

**Redirects are not followed.** Spec §4: "Do not follow redirects automatically. A
proposed redirect must pass a fresh scope decision or stop. Reject ambiguous URL
encodings and unsupported schemes. Preserve host/TLS validation when binding an
address."

**The ceilings are proposals, not approvals.** "Proposed ceilings of one
request/second and one in-flight request per target, 1 MiB response and 10-second
timeout require D06 profile review before activation; they are not proof of
harmlessness."

**Stop is a measured target, not an instant.** C02: prevent new outbound requests
within five seconds of detection, terminate affected workers within thirty seconds,
and "already-transmitted requests cannot be recalled" — abort open connections where
possible, send no follow-up traffic, record residual exposure. "These are provisional
measured acceptance ceilings, not instantaneous-stop claims."

## 2. What is already built, and what it settles

`egress.py` models the decision, with 40 tests. It deliberately does not resolve DNS,
open sockets or follow anything: "Address resolution is an *input* supplied by the
boundary that actually performed it."

So the decision layer exists and D06 is not about inventing it. D06 is about **what
enforces it**, and the modelled decision turns out to constrain that choice sharply.

## 3. The constraint that decides the mechanism (measured)

`evaluate_destination` requires, for **every** request: scheme, host, port, **path**,
method, whether it came from a redirect, whether that redirect was revalidated, the
**resolved addresses**, and the **pinned address**. A probe ran the real decision with
only the information each candidate mechanism can actually observe:

```
broker performs the request (full URL visible)          -> PERMIT
CONNECT tunnel proxy (host:port only, path unknown)     -> DENY ('PATH_NOT_IN_SCOPE',)
CONNECT tunnel, path guessed as root                    -> DENY ('PATH_NOT_IN_SCOPE',)
network-layer allowlist only (host known, path unknown)  -> DENY ('PATH_NOT_IN_SCOPE',)
broker, request to an excluded path                     -> DENY ('PATH_EXCLUDED',)
broker, redirect not revalidated                        -> DENY ('REDIRECT_REQUIRES_FRESH_DECISION',)
broker, redirect revalidated                            -> PERMIT
```

**A mechanism that sees only `host:port` cannot operate this boundary at all.** Not
"less safely" — it denies every request, because `path` is a required input and the
decision is deny-by-default. A TLS-tunnelling forward proxy and a network-layer egress
allowlist both see only `host:port` for an HTTPS target.

The same probe on address pinning:

```
pinned address still in the resolved set                -> PERMIT
host now resolves elsewhere (rebind)                    -> DENY ('FORBIDDEN_DESTINATION', 'DESTINATION_NOT_PINNED')
no address pinned at all                                -> DENY ('DESTINATION_NOT_PINNED',)
```

DNS rebinding is caught only if the component that connects **pins** the address it
validated and refuses when the host later resolves elsewhere. A mechanism that
delegates resolution to the worker cannot do that.

**Therefore the boundary must originate the connection, not tunnel it.** That is a
design conclusion from code that already exists, and it is the single most useful thing
in this pack. The probe is at `tools/d06_egress_probe.py`; it reports and asserts
nothing, like its D04 counterpart.

*Caveat:* this constrains the mechanism given the decision as modelled. The authority
could instead change the decision — approving host-level scope only, with no path
restriction — but that would discard `approved_paths`, `excluded_paths` and the
ambiguous-encoding check, and spec §4 requires all three. Naming that as the
alternative is more honest than presenting the constraint as physics.

## 4. Mechanism options

| | A — Egress broker performs the request | B — TLS-terminating proxy | C — Network-layer allowlist only | D — Cooperative worker reporting |
|---|---|---|---|---|
| How | The worker has no route out; it asks the broker, which decides, resolves, pins, connects and returns the response | Worker's only route is a proxy that terminates TLS, inspects each request, re-originates it | Default-deny egress with an allowlist of target hosts; the scanner is configured to stay in scope | The worker tells the boundary what it intends to send and waits for approval |
| Can supply `path` | Yes | Yes | **No** | Yes |
| Can pin the address | Yes | Yes | Partially (firewall-level) | No — the worker resolves |
| Survives a compromised worker | Yes | Yes | **No** — any allowlisted host, any rate | **No.** A compromised worker simply does not report. Fails the threat model's central assumption |
| Preserves host/TLS validation | Yes — the broker validates the real certificate as the connecting party | Needs care: the proxy must validate the upstream certificate properly, and the worker then trusts the proxy's own CA | n/a | n/a |
| Per-target rate and in-flight accounting | Natural — one component sees every request | Natural | Crude | Unreliable |
| 1 MiB response cap | Natural — the broker reads the body | Natural | **No** | No |
| Scanner compatibility | The hard part: the scanner must be able to route through it. ZAP's own HTTP stack is the case to prove | Standard `HTTPS_PROXY` support is common | Transparent to the scanner | Requires scanner modification |
| Verdict | **Satisfies the modelled decision**; feasibility turns on scanner integration | Satisfies it, at the cost of a trust-store and certificate-validation design | **Cannot operate the decision** (§3) | **Ruled out by the threat model** |

C is still worth having **underneath** A or B as defence in depth — a default-deny
network policy is what makes "the worker has no route out" true rather than
conventional. It cannot be the boundary; it can be the floor.

**The open question D06 must answer, which this pack cannot:** whether the selected
scanners can be made to route every request through A or B. For ZAP that is a
configuration question with a factual answer; nobody has tested it, and no scanner may
run yet (D04). Until it is tested, A-versus-B is a choice between two designs whose
feasibility is assumed.

## 5. Element 1 — data flow at the boundary

The flow the spec describes, with the boundary marked:

```
assessor -> API (authenticates, derives organization membership)
         -> policy service (current authorization + profile)
         -> orchestrator (leases a specific job, mints a short-lived grant)
         => EGRESS BOUNDARY  <- grant validation happens HERE as well as in the worker
            - validates grant: organization, job, target, profile, destination limits, expiry
            - decides per request: scheme/host/port/path, encoding, redirect state
            - resolves and PINS the address; refuses if the host moves
            - applies per-target rate, in-flight, response-size and timeout limits
            - consults integrity-admission state and generation (C02)
         -> target system (owned lab only, until B1 of the prohibited list is satisfied)
worker  -> admission validator (untrusted output) -> trusted core
```

Two properties of this flow are load-bearing and easy to lose in implementation:

- **The worker never holds the authority.** It cannot mint or extend a grant, and the
  boundary re-validates rather than trusting what the worker presents.
- **The boundary consults trusted state, or a bounded permit whose expiry cannot
  exceed the stop budget.** C02 is explicit, and it is what stops a cached approval
  from outliving a stop.

**Egress-specific threats** are already enumerated in `THREAT_MODEL.md`: T1
(compromised worker reaches an unauthorised system) is its critical threat and this
boundary is the whole mitigation; T12 (scope creep into discovered systems); T13
(resource exhaustion); and T15 (a customer-hosted instance that can relax its own
ceilings), which is deployment-model-dependent and unresolved. This pack does not
restate them; D06's "data-flow/threat model" evidence is that document plus this
section.

## 6. Element 2 — fail-closed decisions

Every row is a denial by default. The spec's wording is quoted where it governs.

| Condition | Required behaviour | Source |
|---|---|---|
| Policy service unavailable | Deny. "Loss of the policy service or current revocation information fails closed" | Spec §3 |
| Revocation state stale or unavailable | Deny, and mark integrity-admission Untrusted | C02 |
| Grant expired, or expiry beyond the stop budget | Deny | C02 |
| Authorization revision stale | Deny | Spec §3 |
| Active stop | Deny | Spec §3 |
| Self-approval in the authorization record | Deny | Spec §3 |
| Ambiguous target identity | Deny | Spec §3 |
| Host resolves away from the pinned address | Deny (`DESTINATION_NOT_PINNED`, `FORBIDDEN_DESTINATION`) | Spec §4; modelled |
| Proposed redirect without a fresh decision | Deny (`REDIRECT_REQUIRES_FRESH_DECISION`) | Spec §4; modelled |
| Ambiguous URL encoding, or unsupported scheme | Deny | Spec §4; modelled |
| Path outside approved scope, or inside an exclusion | Deny (`PATH_NOT_IN_SCOPE`, `PATH_EXCLUDED`) | Spec §4; modelled |
| Integrity-admission Untrusted | Revoke grants and leases, deny every new outbound request, retry and renewal, stop running jobs | C02 |
| Audit path failed, journaling or anchoring unavailable | **Stop still enforced.** "Stop enforcement must not depend on successful journaling or anchoring" | C02 |
| Service restarted | Scans do **not** resume. "Restarting a service does not restart scans"; resume needs an authorised decision, a new integrity generation, and fresh scope/revocation/profile/budget checks | C02 |
| Coverage after a stop | `Stopped`, `Partial` or `Failed` with the cause — "never Complete by default" | C02; modelled in `coverage.py` |

One design note worth carrying into implementation: `egress.py` has **no wildcard
language** for paths, on purpose — segment-aware prefix matching only, because "a glob
syntax is how that guessing creeps in". A profile format that introduces globs would
quietly widen scope.

## 7. Element 3 — worker escape test specification

The spec's own scenario list (§"Add scenarios for...") plus F05's acceptance evidence,
turned into named cases. **None has run**; they need F02–F05 and an authorised
laboratory.

| # | Case | Pass condition |
|---|---|---|
| E1 | DNS rebinding — host resolves to the approved address at validation, elsewhere at connect | Request denied; pinned address enforced; residual exposure recorded if a connection opened |
| E2 | Redirect escape — target returns a 302 to an out-of-scope host | Not followed; a fresh scope decision is required and denies |
| E3 | Redirect to an in-scope host but excluded path | Denied on the exclusion |
| E4 | Direct worker connection attempt, bypassing the boundary | No route exists; attempt fails and is recorded |
| E5 | Stale grant — worker replays a grant after revocation | Denied at the boundary, not only at the worker |
| E6 | Grant with expiry beyond the stop budget | Rejected when minted, not at use time |
| E7 | Ambiguous encoding — double-encoded traversal in the path | Denied |
| E8 | Unsupported scheme (`file:`, `gopher:`, `ftp:`) | Denied |
| E9 | Rate ceiling — worker attempts 10 req/s against a 1 req/s profile | Throttled or denied at the boundary; the worker cannot raise it |
| E10 | In-flight ceiling — worker opens a second concurrent request to one target | Denied |
| E11 | Response-size ceiling — target returns 50 MiB against a 1 MiB cap | Truncated or aborted; result marked truncated; admission's envelope limit not relied on as the only cap |
| E12 | Timeout — target holds the connection open past 10 s | Aborted |
| E13 | Emergency stop — stop issued mid-assessment | No new outbound request after 5 s; workers terminated within 30 s; measured with independent boundary timestamps |
| E14 | Stop with the audit path broken | Stop still enforced; no dependence on journaling or anchoring |
| E15 | Restart after stop — services bounce | Job stays stopped; resume requires an explicit authorised decision |
| E16 | Connection-pool tenant reuse — tenant A's pooled connection serves tenant B | Denied; tenant context never inherited from a pool |
| E17 | Integrity Untrusted mid-flight — chain mismatch during a scan | Grants revoked by generation change; running jobs stopped; cached approval does not continue |

E13's measurement requires "independent boundary timestamps under the approved 10-job
laboratory workload" (T03), which means the clock is not the worker's.

## 8. Element 4 — request limits

| Limit | Proposed value | Governs | Status |
|---|---|---|---|
| Requests per second, per target | 1 | Boundary throttle | Proposed; **D06 approves or amends** |
| In-flight requests, per target | 1 | Boundary concurrency | Proposed; D06 |
| Response size cap | 1 MiB | Boundary read | Proposed; D06 |
| Request timeout | 10 s | Boundary connect/read | Proposed; D06 |
| Web assessment maximum | 60 min | Profile ceiling | Retained from v1.3 |
| Source assessment maximum | 45 min | Profile ceiling | Retained from v1.3 |
| Dependency assessment maximum | 30 min | Profile ceiling | Retained from v1.3 |
| Outbound stop | within 5 s of detection | Stop budget | Provisional measured ceiling (C02) |
| Worker termination | within 30 s | Stop budget | Provisional measured ceiling (C02) |

Two things D06 should state explicitly rather than leave implied:

1. **Where each limit is enforced.** A ceiling the worker applies to itself is not a
   control. All four per-request limits belong at the boundary.
2. **That a profile may only tighten.** `admission.AdapterLimits` already takes this
   position for adapter output — "A reviewed profile may tighten any of these. None may
   be removed" — and the same rule should bind egress profiles, or a profile becomes a
   way to widen scope without a decision (prohibited-capability A10).

## 9. Element 5 — profile approval

A profile is the per-target bundle of what may be requested and how fast. D06's
evidence requires *profile approval*, which means two artefacts, neither of which
exists:

- **A profile schema**: target identity (scheme, host, port), approved paths,
  excluded paths, permitted methods and classes, the four per-request limits, the
  assessment maximum, and the assessment mode (passive, or safe-active only where
  B2 of the prohibited list is satisfied).
- **An approval record per profile**: who approved it, against which target
  authorisation revision, when, and its review date. A profile inherits nothing by
  default; approving one does not approve a variant.

Proposed rule, for D06 to accept or reject: **a profile change is a new approval, not
an edit.** Versioned, with the old version retained, because coverage manifests and
closure proofs reference the profile digest they ran under (`profile_digest` is already
part of `ExpectedBinding` and of the coverage manifest).

## 10. Recommendation (a proposal, not a decision)

1. **Select mechanism A** — a broker that performs the request — **with C underneath
   it** as a default-deny network floor, *conditional on* proving that the selected
   scanners can route through it (§4's open question).
2. **Approve the four per-request ceilings as proposed**, with the explicit statements
   in §8: enforced at the boundary, and a profile may only tighten.
3. **Adopt the fail-closed table in §6 as the specification**, since every row is
   already quoted from an approved document — D06's contribution is making it one
   reviewable list rather than fifteen sentences in four places.
4. **Adopt §7 as F05's test specification**, so the escape tests are written before the
   boundary rather than after it.
5. **Defer the A-versus-B decision explicitly** if scanner routing cannot be tested
   yet, rather than selecting A on an assumption. A recorded "A, subject to routing
   proof" is honest; an unqualified A is not.

## 11. What must be verified before §12 is signed

1. **Scanner routing.** Can ZAP, and the D04-selected software adapter, be configured
   so that every request traverses the boundary? Needs a scanner, so it needs D04 and
   laboratory authorisation.
2. **TLS posture under the chosen mechanism.** Where the boundary originates the
   connection, confirm it performs full certificate and hostname validation as the
   connecting party, and that "preserve host/TLS validation when binding an address" is
   satisfied in the pinned-address case specifically.
3. **Stop budget measurement.** E13 and E14 under the approved 10-job workload, with
   independent boundary timestamps.
4. **The escape suite, run.** §7's seventeen cases, with results recorded per T01 and
   T03.
5. **Profile schema reviewed** against §6's no-wildcard constraint and §8's
   tighten-only rule.

Items 1, 3 and 4 require a running platform. They are F05 work that D06 authorises,
not prerequisites D06 can wait for — which is why the mechanism decision has to be
recorded as conditional if its feasibility is untested.

## 12. Decision record — unsigned

| Field | Value |
|---|---|
| Enforcement mechanism selected | *(not selected)* |
| Conditional on | |
| Per-request ceilings approved as proposed, or amended | |
| Fail-closed table adopted | |
| Escape test specification adopted | |
| Profile schema and approval rule adopted | |
| Decision | *(Approve / Approve with conditions / Hold / Redirect — not recorded)* |
| Accountable authorities (named, security and platform) | |
| Date | |
| Review date | |

Until this is completed, F05 stays blocked, every proposed ceiling stays unapproved
and inactive, and no scanner traffic may occur — which is also the current state for
other reasons (D04, and prohibited-capability B3).

## 13. Provenance and limits

- **Sources.** Integrated Baseline v1.6 (Appendix E.3 D06; E.5 F05/F06; the U01–U03
  integration amendment), Engineering Specification v1.6 (§3 authorization, §4 egress
  and redirect handling, §8 worker isolation, the C02 amendment, the proposed ceilings
  and stop targets), and this repository's `egress.py`, `integrity.py`, `coverage.py`,
  `docs/requirements/THREAT_MODEL.md` and `docs/requirements/PROHIBITED_CAPABILITIES.md`.
- **Measured here.** §3 only, against the real `egress.py`, via
  `tools/d06_egress_probe.py`. It establishes what information the decision requires —
  not that any mechanism works, which needs a running platform.
- **Not measured.** Every feasibility, latency and stop-timing statement. Each is
  labelled.
- **No active testing** was performed or is authorised.
- **Drafted by an AI agent**, requiring competent human review. The same agent wrote
  `egress.py`, which is the conflict H01 exists to resolve — §3's constraint is a
  reading of that module's requirements, and a reviewer should check it rather than
  take it on trust.
