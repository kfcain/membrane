# Membrane check report

> **DEMONSTRATION RUN.** This run passed `--allow-nonlive`. Fixture and simulated records count as eligible. This report is a demonstration. It is not an assessment.

- Run id: `22d5eb44-9387-5fa6-92e7-7a5242762602`
- Assessment time: `2026-09-28T03:08:08Z`
- Evidence directories: `var/evidence`, `fixtures/evidence`
- Input records: 34
- results.json SHA-256: `157da4f5b7c68a64abaa24468a58f795130f9639d7236e382f400c335dde5ce2`

## Check status counts

| PASS | FAIL | NO_EVIDENCE | STALE | INELIGIBLE |
| ---: | ---: | ---: | ---: | ---: |
| 6 | 5 | 0 | 0 | 0 |

## Checks

| Check | Title | Status | Offending | Examined | Reason |
| --- | --- | --- | ---: | ---: | --- |
| AGT-INV-01 | No unregistered agent workloads | **FAIL** | 1 | 7 | 1 offending item(s) out of 7 examined |
| AGT-INV-02 | No manifest drift on running agents | **FAIL** | 1 | 5 | 1 offending item(s) out of 5 examined |
| AGT-IAM-01 | No model-provider credentials outside the vault | **FAIL** | 1 | 2 | 1 offending item(s) out of 2 examined |
| AGT-IAM-02 | One identity per agent | **PASS** | 0 | 5 | 0 offending items out of 5 examined |
| AGT-AU-01 | Every tool execution has an allow decision | **PASS** | 0 | 5 | 0 offending items out of 5 examined |
| AGT-AC-01 | Irreversible actions have a bound approval | **PASS** | 0 | 1 | 0 offending items out of 1 examined |
| AGT-AC-02 | Delegator present where the manifest requires one | **PASS** | 0 | 4 | 0 offending items out of 4 examined |
| AGT-SC-01 | Egress stays inside the manifest list | **FAIL** | 1 | 5 | 1 offending item(s) out of 5 examined |
| AGT-CM-01 | Deploys pass every gate | **FAIL** | 1 | 5 | 1 offending item(s) out of 5 examined |
| AGT-TST-01 | Canary probes pass daily | **PASS** | 0 | 8 | 0 offending items out of 8 examined; 2 probe(s) not run: egress_fqdn_outside_manifest, egress_direct_ip |
| AGT-IR-01 | Kill drill inside 90 days and inside SLA | **PASS** | 0 | 1 | 0 offending items out of 1 examined |

## Control rollup

MET means every mapped check is PASS. NOT MET means no mapped check is PASS. PARTIAL is the rest.

### NIST SP 800-53 Rev 5

MET 10, PARTIAL 0, NOT MET 11.

| Control | Status | Checks |
| --- | --- | --- |
| AC-3 | MET | AGT-AU-01 PASS, AGT-AC-01 PASS, AGT-AC-02 PASS |
| AC-3(2) | MET | AGT-AC-01 PASS |
| AC-4 | NOT MET | AGT-SC-01 FAIL |
| AU-2 | MET | AGT-AU-01 PASS |
| AU-12 | MET | AGT-AU-01 PASS |
| CA-7 | MET | AGT-TST-01 PASS |
| CM-2 | NOT MET | AGT-INV-02 FAIL |
| CM-3 | NOT MET | AGT-INV-02 FAIL, AGT-CM-01 FAIL |
| CM-3(2) | NOT MET | AGT-CM-01 FAIL |
| CM-8 | NOT MET | AGT-INV-01 FAIL |
| CM-8(3) | NOT MET | AGT-INV-01 FAIL |
| IA-4 | MET | AGT-IAM-02 PASS |
| IA-5 | NOT MET | AGT-IAM-01 FAIL |
| IA-5(7) | NOT MET | AGT-IAM-01 FAIL |
| IA-9 | MET | AGT-IAM-02 PASS |
| IR-3 | MET | AGT-IR-01 PASS |
| IR-4 | MET | AGT-IR-01 PASS |
| SA-11 | NOT MET | AGT-CM-01 FAIL |
| SC-7 | NOT MET | AGT-SC-01 FAIL |
| SC-7(5) | NOT MET | AGT-SC-01 FAIL |
| SI-6 | MET | AGT-TST-01 PASS |

### SCF 2026.3 assessment objectives

MET 11, PARTIAL 0, NOT MET 12.

| Control | Status | Checks |
| --- | --- | --- |
| AAT-07.1_A02 | NOT MET | AGT-INV-01 FAIL |
| AAT-07.1_A03 | NOT MET | AGT-INV-02 FAIL |
| AAT-28.5_A01 | NOT MET | AGT-CM-01 FAIL |
| AAT-28.10_A02 | NOT MET | AGT-CM-01 FAIL |
| AAT-36.12_A01 | MET | AGT-AC-01 PASS |
| AAT-36.12_A02 | MET | AGT-AC-01 PASS |
| AAT-39.2_A02 | NOT MET | AGT-SC-01 FAIL |
| AAT-39.3_A03 | MET | AGT-AU-01 PASS |
| AAT-39.11_A02 | NOT MET | AGT-SC-01 FAIL |
| AAT-39.13_A01 | MET | AGT-IR-01 PASS |
| AAT-39.14_A01 | MET | AGT-TST-01 PASS |
| AAT-39.19_A01 | MET | AGT-IAM-02 PASS |
| AAT-39_A03 | MET | AGT-AC-01 PASS |
| AAT-40.1_A01 | MET | AGT-AU-01 PASS |
| AST-09_A04 | NOT MET | AGT-INV-01 FAIL |
| CFG-08.2_A07 | NOT MET | AGT-INV-02 FAIL |
| CFG-17.2_A04 | NOT MET | AGT-IAM-01 FAIL |
| CHG-07_A01 | NOT MET | AGT-CM-01 FAIL |
| CPL-07_A06 | MET | AGT-TST-01 PASS |
| IAC-14.3_A01 | NOT MET | AGT-IAM-01 FAIL |
| IAC-36_A02 | MET | AGT-IAM-02 PASS |
| IRO-09_A04 | MET | AGT-IR-01 PASS |
| NET-04_A03 | NOT MET | AGT-SC-01 FAIL |

## Findings

### AGT-INV-01 No unregistered agent workloads

- cluster=prod-use1-agents; namespace=agents; name=shadow-summarizer; kind=Deployment; service_account=default; reason=no_agent_id_label_in_agent_namespace (record e7e2d7b1-9d9e-5e25-b61a-1cd898928d82)

### AGT-INV-02 No manifest drift on running agents

- cluster=prod-use1-agents; namespace=agents-sandbox; name=code-runner; agent_id=code-runner; observed_sha256=9f2c4b7e1a3d5f608192a3b4c5d6e7f8091a2b3c4d5e6f708192a3b4c5d6e7f8; registry_sha256=c66b040b5bc10e52d9a43ba59e78984abb0c05477cd7dd85f0559beb9c0cf3e9; reason=manifest_hash_mismatch (record e7e2d7b1-9d9e-5e25-b61a-1cd898928d82)

### AGT-IAM-01 No model-provider credentials outside the vault

- provider=openai; location=git@git.example.com:analytics/notebooks.git:summarize/run.py:14; fingerprint=sha256:4b1f0c9e2d7a6b3c; scanner=gitleaks 8.21.2 (record 588b1f3c-eeec-5d95-8899-9403ac617f4a)

### AGT-SC-01 Egress stays inside the manifest list

- agent_id=invoice-reconciler; namespace=agents-finance; pod=invoice-reconciler-7d9f8c6b5-x2k4q; destination_fqdn=pastebin.example.net; destination_ip=198.51.100.23; port=443; count=3; reason=destination_not_in_manifest (record 8bb3415a-0f44-5a6f-be26-919af5a89d3f)

### AGT-CM-01 Deploys pass every gate

- run_id=ci-ticket-triager-31; agent_id=ticket-triager; commit=bbe17c3617089ba298559cc5b6cd0e490271d2a0; image_digest=sha256:2222222222222222222222222222222222222222222222222222222222222222; failed_gates=["evals:skipped", "evals_score:None<0.92"] (record f825d624-3a20-563b-a7d8-359b8f10617f)

## Limitations

- A check result reports what the evidence records show at the assessment time. It does not show that the records are true.
- A PASS covers only the population in the records. A workload, flow, or call that no collector saw is not in the population.
- A control status here is a rollup of mapped checks only. It is not an assessor determination and it does not cover the full control.
- The SCF and NIST SP 800-53 mappings are membrane's own. Neither the SCF Council nor NIST reviewed them.
- Membrane does not seal results. Beacon seals them. Beacon keeps the status word unverified.
- This run is a demonstration. Fixture and simulated records are not observations of a real system.
