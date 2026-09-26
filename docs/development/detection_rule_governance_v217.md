Detection-as-Code Governed Lifecycle (V2.17)
============================================

Purpose
-------

Step 27 adds **Detection-as-Code**: a governed lifecycle over the controlled
detection-rule repository.  A manifest at ``rules/manifest.yaml`` is the
single governed inventory (28 Sigma + 25 YARA rules), and every rule must
pass a **fail-closed, server-side validation pipeline** — real Sigma/YARA
engine compile plus positive/negative fixtures, source-integrity hashing,
secret-safety, metadata and severity checks — before it may be **released**
and **deployed** into the governed registry that the existing Step 26
engines consume.

> Governance == validation, not execution.  ``deployed`` means the rule is
> registered in the deployed registry served to the detection engines; the
> engines still evaluate every target at their own gate and record their own
> ``DetectionResult`` rows.  Validation status always comes from the real
> engines — it is never guessed, cached from a client, or fabricated.

Design principles:

* **Truthful inventory, always.**  Sigma = 28, YARA = 25, Total = 53 — never
  padded.  Synthetic rules used by demos/tests live in temporary rules roots
  and their DB rows are cleaned up, so ``build_deployed_registry()`` always
  reflects the shipped inventory.
* **Server-side trust.**  Every ``validate`` recomputes the source SHA-256
  server-side and replays the content through the real engines.  Clients can
  never supply a hash, a fixture path, or a validation outcome.  No
  client-supplied filesystem paths exist anywhere.
* **Roles, not bodies.**  ``ciso`` = read-only, ``analyst`` = read +
  validate, ``admin`` = full lifecycle (release, deploy, rollback,
  enable/disable).  Bodies carry only ``rule_id`` / version / bump metadata.
* **Strict semver, explicit bumps.**  Content changes require an explicit
  new version + ``bump_class`` + accountability ``change_reason``; the
  system never guesses a version and rejects a declared bump class that does
  not match the actual ``MAJOR.MINOR.PATCH`` transition.
* **Deterministic identities.**  Version/release/change rows use UUIDv5 over
  content (``version_identity``, ``release_identity``, ``change_identity``),
  so re-runs are idempotent and a content change always forks a new version
  identity.
* **Fail-closed.**  Validation, rollback source verification, and the show
  "disabled but registered" semantics never degrade silently.

Pipeline
--------

::

    rules/manifest.yaml            # single governed inventory (28+25)
        -> detection_as_code_generate_fixtures_manifest.py   (generator)
        -> detection_as_code_validate_all.py                 (whole set)
        -> detection_as_code_onboard.py                      (validate→release→deploy)
        -> detection_as_code_quality_report.py               (governance report)
    POST /api/detection-as-code/validate        # validate one rule
        -> manifest entry -> server hash -> secret scan -> type/severity/metadata
        -> real engine compile -> positive/negative fixtures -> ValidationOutcome
    POST /api/detection-as-code/release         # release a validated version
    POST /api/detection-as-code/deploy          # deploy -> governed registry
        -> build_deployed_registry()            # snapshot the engines read
    POST /api/detection-as-code/rollback        # roll back to a released version
    POST /api/detection-as-code/enabled         # enable/disable a governed version
    GET  /api/detection-as-code                 # latest versions (paged)
    GET  /api/detection-as-code/{rule_id}       # full lifecycle (read model)

Backend pieces
--------------

* ``app/schemas/detection_as_code.py`` — the V2.17 contract: closed
  vocabularies (``BumpClass``, ``ValidationOutcome``, ``ReleaseState``,
  ``DeploymentState``, ``ChangeKind``), strict semver helpers
  (``parse_semver`` / ``classify_bump``), deterministic identities, the
  manifest schema (unique rule ids, relative paths only, sha256 pins),
  ``ValidationDetail`` (one flag per real gate), persisted read models
  (``DetectionRuleVersionRecord``, ``DetectionRuleReleaseRecord``,
  ``DetectionRuleChangeRecord``, ``DetectionAsCodeRulePage``,
  ``DetectionAsCodeRuleDetail``) and the mutation payloads
  (``ValidateRuleRequest`` / ``ReleaseRequest`` / ``DeployRequest`` /
  ``RollbackRequest`` / ``SetEnabledRequest``).
* ``app/models/detection_rule_{version,release,change}.py`` + migration
  ``4c8f2d1a9b3e`` — the governed tables.
  ``release.version_id`` references ``detection_rule_versions.id`` (the
  uuid4 PK), **not** the deterministic identity, and
  ``version.rollback_from`` also references ``versions.id``; short FK names
  are below the 63-char Postgres identifier limit.
* ``app/services/detection_as_code/`` — layered service modules:
  ``hashing`` (SHA-256 over raw bytes), ``paths`` (containment guards:
  no ``..`` / absolute / drives / symlink escapes / executable or binary
  sources), ``security`` (credential-value leakage scanner that tolerates
  detection markers like bare ``client_secret=``), ``fixtures``
  (per-rule positive/negative fixtures), ``manifest`` (load / generate /
  orphan detection), ``repository`` (data access + version/release/change
  rows), ``validation`` (``DetectionRuleValidationService``, one gate per
  contract field, fail-closed), ``lifecycle`` (``LifecycleService``:
  compose validation + persistence + registry), ``quality`` (report
  aggregation), ``exceptions``.
* ``app/api/routes/detection_as_code.py`` — thin transport: every route
  calls one service method and returns a read model under
  ``/api/detection-as-code``.  A role-guard dependency
  (``_require_roles``) enforces the read / validate / lifecycle surface and
  audits every denial as ``detection_as_code.unauthorized_attempt``.
* Scripts: ``detection_as_code_generate_fixtures_manifest.py`` (deterministic
  generator), ``validate_all`` (53/53), ``onboard`` (53/53 validated /
  released / deployed, idempotent), ``quality_report``
  (``all_rules_pass=True``), ``e2e`` (full lifecycle demo, self-cleaning).

HTTP semantics
--------------

* Authentication: missing/invalid token → **401**; role denied → **403**
  ("Insufficient permissions", audited).  Read = admin/analyst/ciso;
  validate = admin/analyst; release/deploy/rollback/enabled = admin.
* ``GET /api/detection-as-code?page=&page_size=`` (page_size max 200),
  ``GET /api/detection-as-code/{rule_id}`` — unknown id → **404**.
* ``POST .../validate`` — unknown rule id → **404**; version without
  ``bump_class`` (or vice versa) or missing ``change_reason`` → **422**;
  content changed without an explicit bump → **409**; identical content is
  idempotent **200**.
* ``POST .../release`` ``/deploy`` ``/rollback`` ``/enabled`` — unknown rule /
  version → **404**; lifecycle conflicts (deploy unreleased, rollback to a
  non-released version, …) → **409**; idempotent transitions → **200**.
* Sanitized infrastructure failures → **503**.

Frontend (dashboard)
--------------------

* ``src/types/api.ts`` — ``BumpClass``, ``ValidationOutcome``,
  ``ReleaseState``, ``DeploymentState``, ``ChangeKind``, the three governed
  read records, ``DetectionAsCodeValidationDetail``,
  ``DetectionAsCodeRulePage``, ``DetectionAsCodeRuleDetail`` and the two
  mutation bodies.
* ``src/api/detectionAsCode.ts`` — ``detectionAsCodeApi.get/list/validate/
  release/deploy/rollback/setEnabled`` using the shared
  ``buildUrl``/``request`` client.
* ``src/pages/detection-as-code-page.tsx`` — governed-rule table (type,
  severity, validation/release/deploy badges, version) with filters and
  paging, plus a lifecycle inspector panel: per-gate validation flags,
  error messages, versioning ledger, and admin-only action buttons
  (Validate / Release / Deploy / Rollback / Enable-Disable) that invalidate
  the list on success.
* ``src/routes/index.tsx`` — route ``/detection-as-code``; sidebar entry
  "Detection as Code" (Operations).

Tests
-----

* ``tests/unit/test_detection_as_code_contract.py`` — semver parsing/order,
  bump classification, deterministic identities, manifest-entry guards
  (traversal / absolute / wrong extension / hash shape), mutation payload
  constraints.
* ``tests/unit/test_detection_as_code_security.py`` — recognized credential
  formats (AWS/JWT/GitHub/Slack/PEM), key/value assignment leaks, marker
  tolerance, determinism.
* ``tests/unit/test_detection_as_code_paths.py`` — traversal / absolute /
  drive / symlink-escape rejection, extension and binary guards.
* ``tests/unit/test_detection_as_code_hashing.py`` — SHA-256 determinism.
* ``tests/unit/test_detection_as_code_manifest.py`` — round-trip,
  deterministic output, orphans / missing sources, corruption handling.
* ``tests/unit/test_detection_as_code_validation.py`` — real-engine
  validation on a synthetic governed rule; each gate fails independently
  under tamper (source, hash, fixtures, leaks) and shipped Sigma rules
  validate 100%.
* ``tests/unit/test_detection_as_code_lifecycle.py`` — validate→release→
  deploy, row persistence, idempotent revalidate/redeploy, content-change
  bump enforcement, rollback (incl. fail-closed source verification),
  enable/disable, deployed registry serving through the real YARA engine.
  Unique rule ids + FK-ordered cleanup (changes → releases → versions).
* ``tests/unit/test_detection_as_code_api.py`` — 401 without token /
  invalid token; 403 for role denials (viewer on read, ciso on validate,
  analyst/ciso on lifecycle); 200 reads with the three SOC roles;
  idempotent admin lifecycle transitions; 404 / 422 semantics.

Scope boundaries
----------------

Step 27 adds **no** SOAR, threat hunting, AI incident reports, knowledge
graph, attack-path visualization, multi-agent debate, attack prediction, AI
playbook generation, digital-twin or purple-team features.  It never
executes arbitrary code from rule content, never accepts client-supplied
filesystem paths or hashes, and never weakens the existing validation /
engine / registry / loader contracts.  There is no GitHub/GitLab/CI-CD
integration — governance happens in-process against the controlled rules
root.