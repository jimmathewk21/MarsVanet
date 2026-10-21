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

## Experimental Status

The repository preserves experiment artifacts and multiple controller versions for reproducibility. The presence of a script, capture, or evidence file does not by itself establish that every defense stage has been validated. Claims about performance and progressive mitigation should be supported by the corresponding experiment outputs.

## Reproducibility

Review the scripts, topology configuration, and evidence files in the relevant methodology directory before running an experiment. Network interfaces, controller processes, software versions, and IP addresses may need to match the original environment.

## Team

Team 14 — Jim Mathew K and Vignesh Ekambaram.
