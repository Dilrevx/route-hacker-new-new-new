# Runtime PoC Validation SOP

> Document status: operational SOP
>
> Last updated: 2026-08-23
>
> Scope: guidance for agents that turn scanner or audit candidates into stable
> runtime evidence, security-model review, and disclosure or closure material.

## Purpose

This SOP captures the workflow pattern used during the Apache latest/default
ActiveMQ HTTP discovery registry validation. It is a prompt for what agents can
consider, not a rigid output contract or a mandatory report schema. Individual
projects may require different runtimes, evidence shapes, and disclosure
formats.

The goal is to remind the agent to keep three questions visible before
escalating a candidate:

1. What is the precise vulnerability hypothesis and required attacker control?
2. Can a stable runtime or focused harness demonstrate the hypothesized
   behavior on the pinned revision?
3. Does the demonstrated behavior violate the project's security model enough
   to justify vendor reporting?

## Useful Inputs

- Candidate finding with project, revision, file paths, and claimed impact.
- Frozen source checkout for the audited revision.
- Current/default-branch freshness evidence, when the workflow is auditing
  present-day project candidates rather than historical CVEs.
- Existing runtime-builder artifacts, if any, including old images, build logs,
  and known one-command runners.
- PoC-agent workspace path and result location, when the caller provides them.

## Suggested Flow

### Step 1: Normalize The Claim

Restate the finding as a concrete hypothesis before building or running a PoC.

Record enough context for another reviewer to understand:

- affected component and entry point;
- attacker preconditions;
- security boundary being crossed;
- observable runtime behavior that would support or weaken the hypothesis;
- reason the behavior is not merely normal product functionality.

For example, the ActiveMQ candidate was narrowed from a broad "HTTP discovery
registry is mutable" claim into separate questions about registry mutation,
downstream discovery-client behavior, listener binding, and vendor security
model.

### Step 2: Inspect Source Before Running PoC

Read the target code paths and write down the exact behavioral contract being
tested. Prefer small snippets over broad paraphrase when snippets make the
reasoning easier to review.

Minimum source questions:

- Which method accepts attacker-controlled input?
- Which method mutates state or performs the sensitive action?
- Which authn/authz, origin, token, or role checks exist on that path?
- Which downstream consumer observes the mutated state?
- Which configuration flag or deployment choice enables the path?

For ActiveMQ, the key source facts were:

- `DiscoveryRegistryServlet#doPut` stores the `service` header in the registry.
- `DiscoveryRegistryServlet#doDelete` removes the `service` header from the
  registry.
- `HTTPDiscoveryAgent#doLookup` reads registry lines as service endpoints.
- `HTTPDiscoveryAgent#start` starts the embedded registry only when
  `startEmbeddRegistry` is true.
- `EmbeddedJettyServer#start` parses the URL for its port and then uses
  `new Server(port)`.

### Step 3: Build Or Reuse A Stable Runtime

Avoid starting PoC-agent work from an unstable or unknown environment.

Common order:

1. Reuse existing runtime-builder artifacts when the target belongs to an older
   dataset or has already been made runnable.
2. If no trustworthy runtime exists, use the pipeline runtime builder to create
   the image or runnable harness first.
3. For library-level behavior, use the smallest faithful harness that exercises
   the affected product code from the pinned source revision.

When practical, the runtime or harness should prove revision identity before
executing the PoC. For Git checkouts, record the actual `git rev-parse HEAD`
and compare it with the audited revision.

### Step 4: Run PoC Agent With Observable Evidence

The PoC should make the relevant state transitions easy to inspect. Prefer
deterministic evidence, but adapt the exact format to the target project and
runtime.

Useful evidence usually answers:

- baseline state before attacker action;
- unauthenticated or low-privileged action result;
- server-side state after attacker action;
- victim or downstream observation after attacker action;
- cleanup or reverse action result;
- whether the run demonstrated the security-relevant behavior or only exercised
  an API.

The PoC artifact should be portable when it will be shared: include enough
source, runner instructions, dependency metadata, and revision context for a
reviewer to rerun it. Do not include local build outputs, raw agent transcripts,
secrets, or absolute local paths.

### Step 5: Independently Challenge The Security Model

After a PoC runs, inspect whether the behavior is expected by the project.
This step prevents reporting product features as vulnerabilities.

Check:

- official security and configuration documentation;
- advisory history and adjacent CVEs;
- public issue tracker and relevant commits;
- tests or examples that show intended deployment assumptions;
- whether the risky behavior is default, optional, authenticated, or explicitly
  trusted-network-only.

For ActiveMQ, the official discovery documentation already warns that an
attacker participating in auto discovery may present itself as a legitimate
broker and catch or manipulate messages. That overlaps with discovery poisoning
and weakens any claim that endpoint publication alone violates the intended
model.

The stronger reportable angle became:

- embedded HTTP registry mutation is unauthenticated when enabled;
- the embedded Jetty listener may bind beyond `localhost` because only the port
  is used;
- documentation and operator expectation may not clearly describe that enabling
  `startEmbeddRegistry=true` starts a writable unauthenticated control plane.

### Step 6: Classify The Outcome Conservatively

Use conservative, model-aware language. The exact labels may differ by batch,
but the reasoning should distinguish:

- reproduced behavior that appears to cross a security boundary;
- reproduced behavior whose security model is unclear;
- reproduced behavior that appears to be expected product behavior;
- runtime evidence that contradicts the vulnerability hypothesis;
- infrastructure or build failures that prevented a fair test;
- skipped cases that failed a freshness, revision, or scope gate.

Avoid treating a successful run as security confirmation by itself. The reviewer
should also validate attacker preconditions and the product security boundary.

### Step 7: Prepare Disclosure Or Closure Artifacts

For vendor reporting, prepare enough material for the maintainer to understand
and reproduce the issue:

- concise subject line with the key boundary issue;
- preconditions stated before impact;
- audited revision and date;
- source excerpts for the critical code paths;
- concise PoC evidence summary;
- portable PoC zip or private reproduction bundle;
- explicit statement that the report is private and unsent publicly;
- open question asking whether the behavior is intended, when the security model
  is unclear.

For closure as expected behavior or non-reportable behavior, preserve:

- source evidence;
- PoC evidence;
- official documentation or maintainer response;
- reason the case is not reportable;
- any hardening or documentation recommendation.

## Example Application: ActiveMQ, 2026-08-23

This section is an example of how the SOP was applied. It is not a required
template for future cases.

### Candidate Triage

- Purpose: Determine whether an Apache latest/default ActiveMQ finding was worth
  PoC-agent validation.
- Scope: ActiveMQ Classic HTTP discovery registry candidate at
  `4c0d70250faed7e3739f7ef14f0d72f1625d42c1`.
- Work performed: Read the scanner claim, identified the registry mutation path, and
  separated default-broker exposure from optional embedded registry exposure.
- Evidence preserved: Source-backed hypothesis focused on an optional embedded
  registry configuration.
- Verification: Source review showed `startEmbeddRegistry` defaults to false.
- Follow-up: Build a focused harness that exercises ActiveMQ product code.

### Stable Runtime And PoC

- Purpose: Prove the registry mutation path and downstream client observation on
  the audited revision.
- Scope: Minimal Maven PoC using `activemq-http` and the ActiveMQ unit-test
  `StubCompositeTransport`.
- Work performed: Built the target `activemq-http` module from the pinned checkout,
  started `EmbeddedJettyServer`, issued unauthenticated PUT/DELETE requests,
  and observed a victim `DiscoveryTransport`.
- Evidence preserved: Portable PoC package and repeatable confirmation log.
- Verification: The PoC showed baseline state, unauthenticated mutation,
  downstream discovery-client observation, and cleanup behavior.
- Follow-up: Treat the behavior as dynamically reproduced while security classification
  remains model-dependent.

### Listener Binding Check

- Purpose: Test the operator-expectation question around `localhost` registry
  URLs.
- Scope: Embedded registry configured as
  `http://localhost:18080/discovery-registry/poc`.
- Work performed: Ran a hold harness, inspected the listening socket, and issued HTTP
  GET/PUT/DELETE through the host LAN address.
- Evidence preserved: Listener and HTTP-access evidence showing the service was
  not limited to loopback in the tested environment.
- Verification: The listener was stopped after testing and no Java hold process
  remained.
- Follow-up: Compare the binding behavior against official docs and public
  advisory history.

### Security-Model Review

- Purpose: Decide whether the case should be reported as a vulnerability,
  hardening issue, or expected behavior.
- Scope: ActiveMQ discovery documentation, security advisories, public
  GitHub/JIRA/list search, and relevant source history.
- Work performed: Checked official discovery warning, searched for
  `DiscoveryRegistryServlet`, `startEmbeddRegistry`, and adjacent HTTP discovery
  CVEs.
- Evidence preserved: Found official general warning that auto discovery can allow an
  attacker to present itself as a legitimate broker. Found adjacent
  HTTP-discovery CVE history, but no public duplicate for unauthenticated
  embedded registry PUT/DELETE or `localhost` wildcard binding.
- Verification: GitHub `main` raw source still contained the same key logic.
- Follow-up: Prepare a private security-boundary clarification with
  configuration-dependent severity language, emphasizing unauthenticated
  mutation plus wildcard binding rather than claiming default broker compromise.

### Disclosure Preparation

- Purpose: Produce a vendor-ready draft without overclaiming.
- Scope: Gmail draft, subject, body, and PoC attachment.
- Work performed: Prepared a cautious subject and body, then used Codex/Gmail tooling to
  update the existing draft and attach the PoC zip. The email was not sent.
- Evidence preserved: Updated Gmail draft addressed to Apache Security with the
  PoC zip attached.
- Verification: The draft update tool reported the new subject, replaced body,
  attached `activemq-http-discovery-registry-poc.zip`, and left the draft
  unsent.
- Follow-up: Preserve maintainer response and use it to update the case
  classification.

## Review Prompts

These prompts are reminders, not required fields. Apply the ones that fit the
target project and adapt the rest.

- Has the audited revision been confirmed? If this is a current-project audit,
  does the freshness gate matter for this batch?
- Can the vulnerability hypothesis be stated with attacker preconditions and
  the intended security boundary?
- Which affected source paths are worth reading before building a runtime?
- Is there an existing runtime-builder artifact or small faithful harness that
  can save time?
- Does the evidence separate environment success from security-relevant
  behavior?
- Is downstream impact visible, or did the PoC only exercise an API?
- Do exposure assumptions such as host binding, role, network reachability, and
  optional configuration change the interpretation?
- Do official docs, advisories, issue trackers, commits, or tests describe the
  behavior as expected?
- What source evidence, PoC evidence, and security-model evidence should be
  preserved for later review?
- Which raw logs, source checkouts, build outputs, local paths, or credentials
  should stay out of committed snapshots?
- Would a disclosure note, hardening note, or closure note help the next
  reviewer?
