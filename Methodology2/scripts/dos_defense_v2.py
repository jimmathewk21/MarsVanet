"""Mobility-aware progressive DoS mitigation controller (Ryu, OpenFlow 1.3).

Methodology 2 controller. Detection/decision logic lives in the
runtime-independent modules ``med2_config`` and ``mobility_detector`` so it can
be unit-tested without Ryu; this file is the thin Ryu/OpenFlow adapter that
applies those decisions.

Progressive mitigation:
    Stage 0 (normal)  : monitor, learn L2, forward.
    Stage 1 (meter)   : rate-limit the offending source with an OFPMeterMod
                        drop band, and KEEP sending matching packets to the
                        controller so the rate can still be observed and
                        Stage 2 escalation remains possible.
    Stage 2 (block)   : install a temporary drop flow with a hard timeout.
                        After the block expires and traffic subsides, the
                        per-source detector is reset so legitimate traffic
                        recovers (no indefinite re-blocking).

IMPORTANT — live validation still required. The AP2 ingress/output ports and
DPID are configurable assumptions (see med2_config); confirm them against
`ovs-ofctl -O OpenFlow13 show ap2` before interpreting mitigation behaviour.
This source cannot be run in a plain container (needs Ryu + a live switch).
"""

import os
import sys
import time
from collections import defaultdict, deque
from pathlib import Path

# Make the sibling pure-Python modules importable regardless of the working
# directory ryu-manager is launched from.
sys.path.insert(0, str(Path(__file__).resolve().parent))

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import (
    MAIN_DISPATCHER,
    CONFIG_DISPATCHER,
    DEAD_DISPATCHER,
    set_ev_cls,
)
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, ethernet, ipv4, udp
from ryu.lib import hub

import med2_config
import mobility_detector as md


class DOSDefense(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(DOSDefense, self).__init__(*args, **kwargs)

        self.cfg = med2_config.Med2Config.from_env()

        self.mac_to_port = defaultdict(dict)
        self.datapaths = {}

        # Per-source sliding-window rate trackers and detector state.
        self.rate_trackers = {}          # key -> PacketRateTracker
        self.source_state = {}           # key -> md.SourceState
        self.installed_meters = defaultdict(set)   # dpid -> {meter_id}

        self.start_time = time.time()

        # Mobility features (validated, with documented fallback).
        self.mobility_records, report = md.load_mobility_features(
            self.cfg.mobility_csv
        )
        if report.ok:
            self.logger.info(
                "Loaded %s mobility records from %s (skipped %s rows)",
                report.record_count, report.path, report.skipped_rows,
            )
        else:
            self.logger.warning(
                "Mobility features unavailable (%s): %s -> base threshold "
                "fallback", report.path, report.error,
            )

        # Handover tracking.
        self.handover_path = Path(self.cfg.handover_csv)
        self.handover_events = deque()
        self.seen_handovers = set()
        self.handover_rate = 0.0
        self.last_handover_check = 0.0

        self.logger.info("Config: %s", self.cfg.as_dict())
        self.logger.info("Handover CSV path: %s", self.handover_path)

        hub.spawn(self.monitor_handovers)

    # --- helpers -----------------------------------------------------------

    def _key(self, dpid, source_ip):
        return (dpid, source_ip)

    def _tracker(self, key):
        tracker = self.rate_trackers.get(key)
        if tracker is None:
            tracker = md.PacketRateTracker(self.cfg.window_seconds)
            self.rate_trackers[key] = tracker
        return tracker

    def _state(self, key):
        state = self.source_state.get(key)
        if state is None:
            state = md.SourceState()
            self.source_state[key] = state
        return state

    def current_threshold(self):
        elapsed = time.time() - self.start_time
        sample = md.nearest_sample(
            self.mobility_records, elapsed, self.cfg.mobility_max_age_seconds
        )
        self._update_handover_rate()
        threshold, _reason = md.select_threshold(
            self.cfg, sample, self.handover_rate
        )
        return threshold, sample

    def _update_handover_rate(self):
        now = time.time()
        window = self.cfg.handover_window_seconds
        while self.handover_events and now - self.handover_events[0] > window:
            self.handover_events.popleft()
        self.handover_rate = len(self.handover_events) * 60.0 / window

    # --- handover monitor --------------------------------------------------

    def monitor_handovers(self):
        while True:
            try:
                if self.handover_path.exists():
                    import csv
                    with open(self.handover_path, newline="") as handle:
                        for row in csv.DictReader(handle):
                            if row.get("current_ap") in (None, "", "NONE"):
                                continue
                            if row.get("previous_ap") in (None, "", "NONE"):
                                continue
                            try:
                                timestamp = float(row["timestamp_unix"])
                            except (ValueError, KeyError, TypeError):
                                continue
                            handover_id = (
                                timestamp,
                                row.get("station", ""),
                                row.get("previous_ap", ""),
                                row.get("current_ap", ""),
                            )
                            if handover_id in self.seen_handovers:
                                continue
                            self.seen_handovers.add(handover_id)
                            self.handover_events.append(timestamp)
                            self.logger.info(
                                "Handover observed: %s -> %s at %.3f",
                                row.get("previous_ap"),
                                row.get("current_ap"),
                                timestamp,
                            )

                self._update_handover_rate()
                now = time.time()
                if now - self.last_handover_check >= 10:
                    self.logger.info(
                        "Recent handovers=%s; handover rate=%.2f/min",
                        len(self.handover_events), self.handover_rate,
                    )
                    self.last_handover_check = now
            except OSError as error:
                self.logger.warning("Could not read handover CSV: %s", error)

            hub.sleep(self.cfg.handover_poll_seconds)

    # --- flow / meter installation ----------------------------------------

    def add_flow(self, datapath, priority, match, actions=None,
                 instructions=None, hard_timeout=0):
        parser = datapath.ofproto_parser
        ofproto = datapath.ofproto
        if instructions is None:
            actions = actions or []
            instructions = [
                parser.OFPInstructionActions(
                    ofproto.OFPIT_APPLY_ACTIONS, actions
                )
            ]
        flow = parser.OFPFlowMod(
            datapath=datapath,
            priority=priority,
            match=match,
            instructions=instructions,
            hard_timeout=hard_timeout,
        )
        datapath.send_msg(flow)

    def _meter_id_for(self, source_ip):
        try:
            last_octet = int(source_ip.split(".")[-1])
        except (ValueError, IndexError):
            last_octet = 1
        return 100 + (last_octet % 256)

    def install_meter(self, datapath, source_ip):
        parser = datapath.ofproto_parser
        ofproto = datapath.ofproto
        meter_id = self._meter_id_for(source_ip)

        # Add the meter only once per datapath to avoid OFPMC_ADD conflicts.
        if meter_id not in self.installed_meters[datapath.id]:
            band = parser.OFPMeterBandDrop(
                rate=self.cfg.meter_rate_kbps, burst_size=self.cfg.meter_burst
            )
            meter = parser.OFPMeterMod(
                datapath=datapath,
                command=ofproto.OFPMC_ADD,
                flags=ofproto.OFPMF_KBPS,
                meter_id=meter_id,
                bands=[band],
            )
            datapath.send_msg(meter)
            self.installed_meters[datapath.id].add(meter_id)

        match = parser.OFPMatch(
            in_port=self.cfg.ap2_in_port,
            eth_type=0x0800,
            ip_proto=17,
            ipv4_src=source_ip,
            ipv4_dst=self.cfg.destination_ip,
        )

        # Stage 1: meter + forward to the victim AND copy to the controller so
        # the detector keeps observing the (now rate-limited) rate and can
        # still escalate to Stage 2. The original version output only to the
        # victim port, which silently prevented escalation.
        instructions = [
            parser.OFPInstructionMeter(meter_id),
            parser.OFPInstructionActions(
                ofproto.OFPIT_APPLY_ACTIONS,
                [
                    parser.OFPActionOutput(self.cfg.ap2_out_port),
                    parser.OFPActionOutput(ofproto.OFPP_CONTROLLER),
                ],
            ),
        ]
        self.add_flow(
            datapath, 60, match, instructions=instructions,
            hard_timeout=self.cfg.meter_hard_timeout,
        )

    def install_temporary_block(self, datapath, source_ip):
        parser = datapath.ofproto_parser
        match = parser.OFPMatch(
            in_port=self.cfg.ap2_in_port,
            eth_type=0x0800,
            ip_proto=17,
            ipv4_src=source_ip,
            ipv4_dst=self.cfg.destination_ip,
        )
        # Drop (empty instruction set) with a hard timeout. No periodic refresh
        # -> the block self-expires and the detector resets, enabling recovery.
        self.add_flow(
            datapath, 100, match, instructions=[],
            hard_timeout=self.cfg.stage2_block_seconds,
        )
        self.logger.warning(
            "Stage 2 temporary UDP block: src=%s dst=%s duration=%ss",
            source_ip, self.cfg.destination_ip, self.cfg.stage2_block_seconds,
        )

    # --- switch lifecycle --------------------------------------------------

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        self.datapaths[datapath.id] = datapath
        parser = datapath.ofproto_parser
        ofproto = datapath.ofproto

        # Clean any stale high-priority drop left from a previous run, but only
        # when a specific attacker is configured. With no configured attacker
        # there is nothing to pre-clean.
        if self.cfg.attacker_ip:
            old_match = parser.OFPMatch(
                eth_type=0x0800, ipv4_src=self.cfg.attacker_ip, ip_proto=17
            )
            datapath.send_msg(parser.OFPFlowMod(
                datapath=datapath,
                command=ofproto.OFPFC_DELETE,
                table_id=0,
                priority=100,
                match=old_match,
                out_port=ofproto.OFPP_ANY,
                out_group=ofproto.OFPG_ANY,
            ))

        # Table-miss -> controller (L2 learning).
        self.add_flow(
            datapath, 0, parser.OFPMatch(),
            [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER)],
        )

        # On AP2, copy victim-bound UDP to the controller for rate monitoring.
        if datapath.id == self.cfg.ap2_dpid:
            self.add_flow(
                datapath, 50,
                parser.OFPMatch(
                    in_port=self.cfg.ap2_in_port,
                    eth_type=0x0800,
                    ip_proto=17,
                    ipv4_dst=self.cfg.destination_ip,
                ),
                [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER)],
            )
            self.logger.info(
                "AP2 monitor flow installed (dpid=%s in_port=%s dst=%s)",
                datapath.id, self.cfg.ap2_in_port, self.cfg.destination_ip,
            )

        self.logger.info("Switch ready: dpid=%s", datapath.id)

    @set_ev_cls(ofp_event.EventOFPStateChange, [MAIN_DISPATCHER, DEAD_DISPATCHER])
    def state_change_handler(self, ev):
        """Track datapaths so a disconnected switch is not used for sends."""
        datapath = ev.datapath
        if ev.state == MAIN_DISPATCHER:
            if datapath.id is not None:
                self.datapaths[datapath.id] = datapath
        elif ev.state == DEAD_DISPATCHER:
            if datapath.id in self.datapaths:
                self.logger.warning("Switch disconnected: dpid=%s", datapath.id)
                del self.datapaths[datapath.id]
                self.installed_meters.pop(datapath.id, None)

    @set_ev_cls(ofp_event.EventOFPErrorMsg, MAIN_DISPATCHER)
    def error_msg_handler(self, ev):
        msg = ev.msg
        self.logger.error(
            "OpenFlow error: type=0x%02x code=0x%02x", msg.type, msg.code
        )

    # --- packet in ---------------------------------------------------------

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        parser = datapath.ofproto_parser
        ofproto = datapath.ofproto
        in_port = msg.match.get("in_port")

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)
        if eth is None:
            return
        ip_pkt = pkt.get_protocol(ipv4.ipv4)
        udp_pkt = pkt.get_protocol(udp.udp)

        # Detection path: victim-bound UDP arriving on the AP2 ingress port.
        monitored = (
            datapath.id == self.cfg.ap2_dpid
            and in_port == self.cfg.ap2_in_port
            and ip_pkt is not None
            and udp_pkt is not None
            and ip_pkt.dst == self.cfg.destination_ip
        )
        if monitored and self._handle_detection(datapath, ip_pkt.src):
            # Source is currently blocked; do not also forward it.
            return

        # L2 learning switch for everything else.
        dpid = datapath.id
        self.mac_to_port[dpid][eth.src] = in_port
        out_port = self.mac_to_port[dpid].get(eth.dst, ofproto.OFPP_FLOOD)
        actions = [parser.OFPActionOutput(out_port)]
        if out_port != ofproto.OFPP_FLOOD:
            match = parser.OFPMatch(
                in_port=in_port, eth_src=eth.src, eth_dst=eth.dst
            )
            self.add_flow(datapath, 1, match, actions)

        out = parser.OFPPacketOut(
            datapath=datapath,
            buffer_id=msg.buffer_id,
            in_port=in_port,
            actions=actions,
            data=msg.data if msg.buffer_id == ofproto.OFP_NO_BUFFER else None,
        )
        datapath.send_msg(out)

    def _handle_detection(self, datapath, source_ip):
        """Run the detector for one monitored UDP packet.

        Returns True when the source is in the blocked stage (caller should not
        forward), False otherwise.
        """
        # If a specific attacker IP is configured, only mitigate that source;
        # other sources still get L2 forwarding.
        if self.cfg.attacker_ip and source_ip != self.cfg.attacker_ip:
            return False

        key = self._key(datapath.id, source_ip)
        now = time.time()

        tracker = self._tracker(key)
        tracker.add(now)
        rate = tracker.rate(now)

        threshold, sample = self.current_threshold()
        state = self._state(key)
        decision = md.decide(state, rate, threshold, now, self.cfg)

        if decision.action != md.ACTION_NONE or decision.over_threshold:
            self.logger.warning(
                "DECISION %s", md.format_decision_log(source_ip, sample, decision)
            )

        if decision.action == md.ACTION_INSTALL_METER:
            self.install_meter(datapath, source_ip)
        elif decision.action == md.ACTION_INSTALL_BLOCK:
            self.install_temporary_block(datapath, source_ip)
        elif decision.action == md.ACTION_RESET:
            self.logger.info("Detector reset for src=%s", source_ip)

        return state.stage == md.STAGE_BLOCK
