# MarsVanet

## DoS Attack Analysis in SDN-Based VANETs: Mobility-Aware Trust-Based Progressive Mitigation

**Team 14**

- Jim Mathew K — 24BCE0493
- Vignesh Ekambaram — 24BCE0651

## Project Overview

This project studies the impact of Denial-of-Service (DoS) traffic in a Software-Defined Networking (SDN)-based Vehicular Ad Hoc Network (VANET). It explores traffic filtering, network performance measurements, vehicle mobility data, and the development of mobility-aware, trust-based progressive mitigation.

## Repository Structure

### Methodology 1 — Baseline and Static Filtering

Contains the earlier single-access-point Mininet-WiFi topology, an earlier static UDP-filtering controller, the analysis report, the live-demo guide, and available experiment evidence.

### Methodology 2 — Mobility-Aware Analysis and Progressive Mitigation

Contains the two-access-point topology, SUMO network and route files, mobility datasets, Ryu controller versions, collection scripts, network measurements, packet captures, and experiment evidence.

## Technologies

- Mininet-WiFi
- Open vSwitch (OVS) and OpenFlow 1.3
- Ryu SDN controller
- SUMO mobility simulation
- Python and shell scripts

## Methodology 2 — module layout (after the MED-2 completion revision)

Detection and mitigation *decision logic* is factored into runtime-independent
modules so it can be unit-tested without Ryu/Mininet/SUMO; the Ryu controller is
a thin adapter that applies those decisions.

- `Methodology2/scripts/med2_config.py` — central, environment-overridable configuration.
- `Methodology2/scripts/mobility_detector.py` — mobility feature validation, threshold policy, sliding-window rate, progressive-mitigation state machine.
- `Methodology2/scripts/dos_defense_v2.py` — Ryu/OpenFlow 1.3 controller (uses the two modules above).
- `Methodology2/scripts/sdn_vanet_2ap.py` — two-AP Mininet-WiFi topology + handover monitor.
- `Methodology2/scripts/paillier_crypto.py` — self-contained Paillier crypto (standard library only).
- `Methodology2/scripts/trust_aggregation.py` — privacy-preserving trust / DoS-evidence aggregation (Observer / Aggregator / Decryptor).
- `Methodology2/scripts/connectivity_test.py` — reproducible connectivity / packet-path diagnosis for the live VM.
- `Methodology2/scripts/detector_demo.py` — runnable logic demonstration (no live runtime needed).
- `Methodology2/tests/` + `Methodology2/run_tests.sh` — automated tests.
- `Methodology2/scenarios/{urban,highway}/` — SUMO scenarios + `build_networks.sh`.
- `Methodology2/results/` — freshly generated benchmark CSVs (kept separate from committed `final_evidence/`).
- `Methodology2/EXPERIMENTS.md`, `IMPLEMENTATION_STATUS.md`, `PENDING_WORK_AND_VALIDATION.md`, `CHANGELOG_HANDOVER.md`.

## Setup and tests

The runtime-independent logic and all of its tests need only the Python
standard library (the earlier `sympy` dependency has been removed):

```
bash Methodology2/run_tests.sh          # 45 unit tests + 5 original checks
python3 Methodology2/scripts/detector_demo.py
```

The live SDN + mobility experiments need Open vSwitch, Mininet-WiFi, Ryu and
SUMO/TraCI on a privileged Linux host/VM. See `requirements.txt` for install
notes and `Methodology2/EXPERIMENTS.md` for the full, reproducible experiment
matrix (urban/highway, baseline/attack/mitigation, recovery, aggregation).

## Experimental Status

The repository preserves experiment artifacts and multiple controller versions
for reproducibility. The presence of a script, capture, or evidence file does
not by itself establish that every defense stage has been validated. The
cryptographic and decision-logic work is covered by automated tests; the live
SDN/mobility claims require the testbed and are **not** certified by the
preparation environment. The committed `final_evidence/final_meter_stats.txt`
still shows `flow_count: 0` and is historical only. See
`Methodology2/IMPLEMENTATION_STATUS.md` and
`Methodology2/PENDING_WORK_AND_VALIDATION.md` for the precise, honest status.

## Reproducibility

Review the scripts, topology configuration, and evidence files in the relevant
methodology directory before running an experiment. Network interfaces,
controller processes, software versions, and IP addresses may need to match the
target environment; all such values are configurable via environment variables
(see `med2_config.py`). Confirm the AP2 OpenFlow ports with `ovs-ofctl show ap2`
before interpreting mitigation behaviour.

## Team

Team 14 — Jim Mathew K and Vignesh Ekambaram.
