"""Windows-native, discrete-event SDN-VANET teaching simulator.

All packet forwarding, radio coverage, traffic shaping and detection in this
module are SIMULATED. This does not instantiate OpenFlow switches or sockets.
The historical Mininet/OVS experiments remain the real OpenFlow evidence.
"""
from __future__ import annotations

from collections import Counter, deque
from copy import deepcopy
from dataclasses import dataclass, field
import math
import json
import random
import threading
from typing import Any

try:
    from .methodology import (md, Med2Config, detector_config, parse_safety_message,
                             check_motion, update_reputation, reputation_policy)
except ImportError:
    from methodology import (md, Med2Config, detector_config, parse_safety_message,
                             check_motion, update_reputation, reputation_policy)

WIDTH, HEIGHT = 1100, 660
ROUTES = [
    [(90, 170), (1010, 170), (1010, 520), (90, 520)],
    [(90, 330), (1010, 330), (1010, 170), (90, 170)],
    [(270, 90), (270, 590), (840, 590), (840, 90)],
]
RSUS = [
    {"id": "RSU-1", "x": 300.0, "y": 185.0, "label": "Northwest gateway"},
    {"id": "RSU-2", "x": 825.0, "y": 185.0, "label": "Northeast gateway"},
    {"id": "RSU-3", "x": 550.0, "y": 505.0, "label": "South gateway"},
]
DEFAULT_CONFIG = {
    "base_pps": 120,
    "flood_pps": 320,
    "stage2_after_sec": 10.0,
    "block_duration_sec": 30.0,
    "m2_meter_kbps": 500,
    "m2_window_sec": 5.0,
    "m2_meter_lifetime_sec": 15.0,
    "m2_reset_sec": 30.0,
    "dense_pps": 90,
    "sparse_pps": 150,
    "handover_floor_pps": 150,
    "m2_monitored_rsu": "*",
    "radio_range": 185,
    "rsu_range": 330,
    "rsu_backhaul_mbps": 2.0,
    "max_reported_speed_kmh": 198,
    "max_acceleration_mps2": 8.0,
    "position_tolerance_m": 10.0,
    "reputation_penalty": 0.20,
    "recovery_every": 5,
    "recovery_gain": 0.02,
    "loss_probability": 0.01,
    "m1_enabled": True,
    "m2_enabled": True,
    "m3_enabled": True,
}
RULES_PRESET = [
    {"id": "rule-example", "priority": 800, "source": "V07", "traffic": "UDP_FLOOD", "rsu": "*",
     "action": "DROP", "rate_kbps": None, "enabled": False, "label": "Example: block V07 flood"},
]


def dist(a: dict, b: dict) -> float:
    return math.hypot(a["x"] - b["x"], a["y"] - b["y"])


def position_on_route(route: list[tuple], progress: float) -> tuple[float, float, int, float]:
    segments = [(route[i], route[(i + 1) % len(route)]) for i in range(len(route))]
    lengths = [math.hypot(b[0] - a[0], b[1] - a[1]) for a, b in segments]
    perimeter = sum(lengths)
    pos = progress % perimeter
    for i, ((ax, ay), (bx, by)) in enumerate(segments):
        length = lengths[i]
        if pos <= length:
            frac = pos / length if length else 0
            return ax + frac * (bx - ax), ay + frac * (by - ay), i, math.degrees(math.atan2(by - ay, bx - ax))
        pos -= length
    return *route[0], 0, 0.0


def route_length(route: list[tuple]) -> float:
    return sum(math.hypot(route[(i + 1) % len(route)][0] - route[i][0],
                          route[(i + 1) % len(route)][1] - route[i][1])
               for i in range(len(route)))


@dataclass
class Vehicle:
    id: str
    route: int
    progress: float
    speed: float
    x: float = 0.0
    y: float = 0.0
    angle: float = 0.0
    rsu: str | None = None
    reputation: float = 1.0
    valid_streak: int = 0
    tx_times: deque = field(default_factory=deque)
    high_since: float | None = None
    blocked_until: float = 0.0
    m2_stage: str = "NORMAL"
    meter_tokens: float = 0.0
    meter_current: int | None = None
    safety_acc: float = 0.0
    data_acc: float = 0.0
    flood_acc: float = 0.0
    sent: int = 0
    delivered: int = 0
    dropped: int = 0
    handovers: int = 0
    last_rsu: str | None = None
    last_report: dict | None = None
    last_safety_valid: bool = True
    last_invalid_reason: str = ""
    meter_buckets: dict = field(default_factory=dict)
    disconnected_at: float | None = None
    detector: object = field(default_factory=md.SourceState)
    meter_expires: float = 0.0
    m2_counter: int = 0
    m2_sample: tuple | None = None
    m2_next_poll: float = 0.0
    m2_rate: float = 0.0
    rate_tracker: object = field(default_factory=lambda: md.PacketRateTracker(5.0))

    def snapshot(self, now: float, threshold: int, m3_enabled: bool) -> dict:
        m3_kbps, m3_label = reputation_policy(self.reputation) if m3_enabled else (None, "DISABLED")
        return {
            "id": self.id, "x": round(self.x, 2), "y": round(self.y, 2), "angle": round(self.angle, 1),
            "speed": round(self.speed, 1), "rsu": self.rsu, "reputation": round(self.reputation, 3),
            "m3_state": m3_label, "m3_kbps": m3_kbps,
            "m2_state": "BLOCK" if now < self.blocked_until else self.m2_stage,
            "pps": round(self.m2_rate, 2), "threshold": threshold,
            "sent": self.sent, "delivered": self.delivered, "dropped": self.dropped,
            "handovers": self.handovers, "last_safety_valid": self.last_safety_valid,
            "last_invalid_reason": self.last_invalid_reason,
        }


class SimEngine:
    def __init__(self, seed: int = 14):
        self.lock = threading.RLock()
        self.seed = seed
        self.rng = random.Random(seed)
        self.running = True
        self.speed_factor = 1.0
        self.t = 0.0
        self.tick_index = 0
        self.config = deepcopy(DEFAULT_CONFIG)
        self.m2_config = detector_config(self.config)
        self.rules = deepcopy(RULES_PRESET)
        self.next_rule = 1
        self.scenario = "normal"
        self.mobility_mode = "builtin"
        self.sumo_bridge = None
        self.attacker = "V07"
        self.victim = "V02"
        self.vehicles: dict[str, Vehicle] = {}
        self.rsus = deepcopy(RSUS)
        self.rsu_tokens = {r["id"]: self.config["rsu_backhaul_mbps"] * 125000 * .3 for r in self.rsus}
        self.rsu_meter_buckets = {r["id"]: {} for r in self.rsus}
        self.events: deque = deque(maxlen=180)
        self.pulses: deque = deque(maxlen=80)
        self.history: deque = deque(maxlen=90)
        self.outcomes: deque = deque(maxlen=60000)
        self.totals = Counter()
        self.reasons = Counter()
        self._history_acc = 0.0
        self.visual_rng = random.Random(seed)
        self.handover_times = deque()
        self._initialize_vehicles()
        self._event("SYSTEM", "Unified SDN-VANET simulator ready", "info")
        self._event("SYSTEM", "12 vehicles online, 3 roadside units available", "info")

    def _initialize_vehicles(self):
        positions = [(0, .05), (1, .58), (2, .13), (0, .45), (1, .12), (2, .65),
                     (0, .26), (1, .72), (0, .77), (2, .88), (1, .35), (0, .92)]
        for i, (route, frac) in enumerate(positions, 1):
            v = Vehicle(f"V{i:02}", route, route_length(ROUTES[route]) * frac, 48 + ((i * 17) % 39))
            v.x, v.y, _, v.angle = position_on_route(ROUTES[route], v.progress)
            self.vehicles[v.id] = v
        self._associate(initial=True)

    def _event(self, kind: str, msg: str, level: str = "info"):
        self.events.appendleft({"id": self.tick_index * 100 + len(self.events), "time": round(self.t, 1),
                                "kind": kind, "message": msg, "level": level})

    def _associate(self, initial=False):
        for v in self.vehicles.values():
            within = [r for r in self.rsus if dist(r, vars(v)) <= self.config["rsu_range"]]
            near = min(within, key=lambda r: dist(r, vars(v)), default=None)
            next_rsu = near["id"] if near else None
            if next_rsu != v.rsu:
                prev = v.rsu
                previous_rsu = prev or (v.last_rsu if v.disconnected_at is not None
                                       and self.t - v.disconnected_at <= 5.0 else None)
                if previous_rsu is not None and next_rsu is not None and previous_rsu != next_rsu:
                    if not initial:
                        v.handovers += 1
                        self.totals["handovers"] += 1
                        self.handover_times.append(self.t)
                        self._event("HANDOVER", f"{v.id}: {previous_rsu} → {next_rsu}", "info")
                elif not initial:
                    self._event("RADIO", f"{v.id}: {'connected to ' + next_rsu if next_rsu else 'outside RSU coverage'}", "info")
                if next_rsu is None:
                    v.last_rsu, v.disconnected_at = prev, self.t
                else:
                    v.last_rsu, v.disconnected_at = next_rsu, None
                v.rsu = next_rsu

    def _threshold(self, v: Vehicle) -> int:
        return self._threshold_context(v)[0]

    def _threshold_context(self, v):
        cfg = self.m2_config
        neighbors = [other for other in self.vehicles.values()
                     if v.rsu and other.rsu == v.rsu]
        sample = ({'time': self.t, 'vehicle_count': len(neighbors),
                   'average_speed': sum(other.speed / 3.6 for other in neighbors) / len(neighbors)}
                  if neighbors else None)
        while self.handover_times and self.handover_times[0] < self.t - cfg.handover_window_seconds:
            self.handover_times.popleft()
        churn = len(self.handover_times) * 60 / cfg.handover_window_seconds
        threshold, reason = md.select_threshold(cfg, sample, churn)
        return threshold, reason

    def _move(self, dt: float):
        if self.mobility_mode == "sumo" and self.sumo_bridge:
            updates = self.sumo_bridge.step(dt)
            for vid, pos in updates.items():
                if vid in self.vehicles:
                    v = self.vehicles[vid]
                    v.x, v.y = pos["x"], pos["y"]
                    v.angle, v.speed = pos["angle"], pos["speed"]
        else:
            for v in self.vehicles.values():
                # 1 simulation coordinate unit = approximately 1 meter.
                v.progress += (v.speed / 3.6) * dt
                v.x, v.y, _, v.angle = position_on_route(ROUTES[v.route], v.progress)
        self._associate()

    def _check_safety_message(self, v: Vehicle, report: dict) -> tuple[bool, str]:
        """Compatibility helper; UI speed_kmh reports convert to original m/s."""
        try:
            message = self._parse_report(report)
            if message.vehicle_id != v.id:
                return False, 'Identity mismatch'
            previous = self._parse_report(v.last_report) if v.last_report else None
            result = check_motion(message, previous, self.config)
            return result.consistent, result.reason
        except ValueError:
            return False, 'Invalid safety JSON'

    @staticmethod
    def _parse_report(report):
        canonical = dict(report)
        if 'speed_kmh' in canonical and 'speed' not in canonical:
            canonical['speed'] = canonical.pop('speed_kmh') / 3.6
        return parse_safety_message(json.dumps(canonical).encode('utf-8'))

    def receive_safety_message(self, source_id, payload):
        """Controller ingress after simulated delivery, with source/ID binding."""
        with self.lock:
            try:
                message = parse_safety_message(payload)
            except ValueError as error:
                self.totals['rejected_safety'] += 1
                self._event('M3 · INPUT', str(error), 'warning')
                return None
            v = self.vehicles.get(source_id)
            if v is None or message.vehicle_id != source_id:
                self.totals['rejected_safety'] += 1
                self._event('M3 · IDENTITY', 'Unknown or mismatched safety source', 'warning')
                return None
            if not self.config['m3_enabled']:
                return None
            previous = self._parse_report(v.last_report) if v.last_report else None
            result = check_motion(message, previous, self.config)
            v.last_safety_valid = result.consistent
            v.last_invalid_reason = '' if result.consistent else result.reason
            if result.consistent:
                v.last_report = dict(vars(message))
            self._observe_reputation(v, not result.consistent, result.reason, result.severity)
            self.totals['observed_safety'] += 1
            return result

    def _send_safety(self, v: Vehicle, is_misinfo: bool, timestamp: float | None = None):
        report = {"vehicle_id": v.id, "timestamp": round(self.t if timestamp is None else timestamp, 4),
                  "x": round(v.x, 2), "y": round(v.y, 2), "speed": v.speed / 3.6}
        if is_misinfo:
            report["speed"] = 280.0 / 3.6
        # Only controller-bound safety reports delivered to an associated RSU
        # update the centralized reputation. Peer copies never double-count.
        observed = v.rsu and self._send(v.id, v.rsu, "SAFETY", 220)
        if observed:
            self.receive_safety_message(v.id, json.dumps(report).encode('utf-8'))
        closest = min((other for other in self.vehicles.values()
                       if other.id != v.id and dist(vars(v), vars(other)) <= self.config["radio_range"]),
                      key=lambda other: dist(vars(v), vars(other)), default=None)
        if closest: self._send(v.id, closest.id, "SAFETY", 220)

    def _observe_reputation(self, v: Vehicle, bad: bool, reason: str = "invalid report", severity=1.0):
        if not self.config["m3_enabled"]: return
        before_rate, before_state = reputation_policy(v.reputation)
        v.reputation, v.valid_streak = update_reputation(
            v.reputation, v.valid_streak, not bad, severity, self.config)
        if bad:
            self.totals["invalid_safety"] += 1
        after_rate, after_state = reputation_policy(v.reputation)
        if after_state != before_state:
            self._event("M3 · REPUTATION", f"{v.id}: {before_state} → {after_state} (trust {v.reputation:.2f})" +
                        (f" · meter {after_rate} kbps" if after_rate else " · meter removed"),
                        "danger" if bad else "success")
        elif bad and (self.tick_index % 8 == 0):
            self._event("M3 · PLAUSIBILITY", f"{v.id}: {reason} · trust {v.reputation:.2f}", "warning")

    def _reset_m2(self, v, reason):
        v.detector = md.SourceState()
        v.rate_tracker = md.PacketRateTracker(self.config['m2_window_sec'])
        v.tx_times.clear()
        v.m2_stage, v.high_since, v.blocked_until = 'NORMAL', None, 0
        v.meter_expires, v.m2_counter, v.m2_sample, v.m2_rate = 0, 0, None, 0
        v.meter_buckets.pop(('m2', 'm2'), None)
        self._event('M2 · RECOVERY', f'{v.id}: {reason}', 'success')

    def _detect_attack(self, v: Vehicle, observe=False):
        """Original M2 decisions, with simulated flow expiry and raw counters.

        NORMAL uses its actual sliding tracker. METER uses one-second counter
        deltas before policy drops, as the original controller's stats adapter
        intends. BLOCK hides dropped packets from observation and self-expires.
        """
        if not self.config['m2_enabled']:
            return
        cfg = self.m2_config
        if v.m2_stage == 'BLOCK':
            if self.t < v.blocked_until:
                return
            threshold, _ = self._threshold_context(v)
            decision = md.decide(v.detector, 0, threshold, self.t, cfg)
            if decision.action == md.ACTION_RESET:
                self._reset_m2(v, 'temporary block expired; resume observation')
            else:
                return
        if v.m2_stage == 'METER' and self.t >= v.meter_expires:
            self._reset_m2(v, 'Stage 1 flow lifetime expired (original adapter recovery)')
        if v.m2_stage == 'METER':
            if observe:
                v.m2_counter += 1
            if self.t + 1e-9 < v.m2_next_poll:
                return
            v.m2_next_poll = self.t + 1.0
            previous = v.m2_sample
            v.m2_sample = (v.m2_counter, self.t)
            if previous is None:
                return  # First statistics sample establishes a baseline.
            elapsed = self.t - previous[1]
            if elapsed <= 0 or v.m2_counter < previous[0]:
                return
            rate = (v.m2_counter - previous[0]) / elapsed
        elif observe:
            v.rate_tracker.window_seconds = cfg.window_seconds
            v.rate_tracker.add(self.t)
            v.tx_times.append(self.t)
            rate = v.rate_tracker.rate(self.t)
        else:
            v.m2_rate = v.rate_tracker.rate(self.t)
            return
        v.m2_rate = rate
        threshold, reason = self._threshold_context(v)
        decision = md.decide(v.detector, rate, threshold, self.t, cfg)
        if decision.action == md.ACTION_INSTALL_METER:
            v.m2_stage, v.high_since = 'METER', self.t
            v.meter_expires = self.t + cfg.meter_hard_timeout
            v.m2_counter, v.m2_sample, v.m2_next_poll = 0, None, self.t + 1.0
            self._event('M2 · DETECTION', f'{v.id}: {rate:.1f} pps >= {threshold}; '
                        f'{self.config["m2_meter_kbps"]} kbps meter; {reason}', 'warning')
        elif decision.action == md.ACTION_INSTALL_BLOCK:
            v.m2_stage = 'BLOCK'
            v.blocked_until = self.t + cfg.stage2_block_seconds
            v.meter_buckets.pop(('m2', 'm2'), None)
            self.totals['m2_blocks'] += 1
            self._event('M2 · STAGE 2', f'{v.id}: persistent rate after dwell; '
                        f'DROP for {cfg.stage2_block_seconds}s', 'danger')

    def _m2_matches(self, source, dst, traffic):
        return bool(source and source.rsu and traffic in ('UDP_FLOOD', 'TELEMETRY')
                    and dst == self.victim
                    and self.config['m2_monitored_rsu'] in ('*', source.rsu))

    @staticmethod
    def _rule_matches(rule: dict, source: str, traffic: str, rsu: str | None) -> bool:
        return (rule["enabled"] and rule["source"] in ("*", source) and
                rule["traffic"] in ("*", traffic) and rule["rsu"] in ("*", rsu))

    def _matching_static_rule(self, source: str, traffic: str, rsu: str | None) -> dict | None:
        if not self.config["m1_enabled"]: return None
        for rule in sorted(self.rules, key=lambda r: (-r["priority"], r["id"])):
            if self._rule_matches(rule, source, traffic, rsu): return rule
        return None

    def _route(self, src: str, dst: str) -> tuple[list[dict], str | None]:
        source = self.vehicles.get(src) or next((r for r in self.rsus if r["id"] == src), None)
        target = self.vehicles.get(dst) or next((r for r in self.rsus if r["id"] == dst), None)
        if not source or not target: return [], None
        a, b = vars(source) if isinstance(source, Vehicle) else source, vars(target) if isinstance(target, Vehicle) else target
        if isinstance(source, Vehicle) and isinstance(target, Vehicle):
            if dist(a, b) <= self.config["radio_range"]:
                return [dict(x=a["x"], y=a["y"]), dict(x=b["x"], y=b["y"])], "V2V"
            if source.rsu and target.rsu:
                r1 = next(r for r in self.rsus if r["id"] == source.rsu)
                r2 = next(r for r in self.rsus if r["id"] == target.rsu)
                route = [dict(x=a["x"], y=a["y"]), dict(x=r1["x"], y=r1["y"])]
                if r1["id"] != r2["id"]: route.append(dict(x=r2["x"], y=r2["y"]))
                route.append(dict(x=b["x"], y=b["y"]))
                return route, "V2I"
        elif isinstance(source, Vehicle) and source.rsu == dst:
            return [dict(x=a["x"], y=a["y"]), dict(x=b["x"], y=b["y"])], "V2I"
        elif not isinstance(source, Vehicle) and isinstance(target, Vehicle) and target.rsu == src:
            return [dict(x=a["x"], y=a["y"]), dict(x=b["x"], y=b["y"])], "I2V"
        return [], None

    def _record_packet(self, src: str, dst: str, traffic: str, size: int, delivered: bool,
                       reason: str, route: list[dict], link: str | None, meter: int | None):
        self.totals["sent"] += 1
        self.totals["delivered" if delivered else "dropped"] += 1
        self.totals["delivered_bytes" if delivered else "dropped_bytes"] += size
        self.reasons[reason] += 1
        malicious = traffic == "UDP_FLOOD"
        self.outcomes.append((self.t, delivered, malicious))
        self.totals["attack_sent" if malicious else "legitimate_sent"] += 1
        if delivered:
            self.totals["attack_delivered" if malicious else "legitimate_delivered"] += 1
        if src in self.vehicles:
            v = self.vehicles[src]
            v.sent += 1
            if delivered: v.delivered += 1
            else: v.dropped += 1
        visual_chance = 0.45 if traffic != "UDP_FLOOD" else .028
        if route and self.visual_rng.random() < visual_chance:
            self.pulses.append({"id": f"{self.tick_index}-{self.totals['sent']}", "t": round(self.t, 3),
                                "src": src, "dst": dst, "traffic": traffic, "ok": delivered,
                                "link": link, "reason": reason, "route": route, "meter": meter})

    def _send(self, src: str, dst: str, traffic: str, size: int):
        # Draw once per offered packet so defenses cannot change the future
        # channel-loss sequence in matched seeded simulation comparisons.
        radio_lost = self.rng.random() < self.config["loss_probability"]
        source = self.vehicles.get(src)
        path, link = self._route(src, dst)
        source_rsu = source.rsu if source else src
        rule = self._matching_static_rule(src, traffic, source_rsu)
        monitored = self._m2_matches(source, dst, traffic)
        if monitored and not (rule and rule['action'] == 'DROP'):
            self._detect_attack(source, observe=True)
        meter_candidates: list[tuple[int, str]] = []
        drop_reason = None
        if rule and rule["action"] == "DROP":
            drop_reason = "M1_STATIC_DROP"
        elif monitored and self.config["m2_enabled"] and self.t < source.blocked_until:
            drop_reason = "M2_TEMP_BLOCK"
        if rule and rule["action"] == "METER": meter_candidates.append((rule["rate_kbps"], "m1"))
        if monitored and self.config["m2_enabled"] and source.m2_stage == "METER":
            meter_candidates.append((self.config["m2_meter_kbps"], "m2"))
        if source and self.config["m3_enabled"] and traffic != "SAFETY":
            rep_rate, _ = reputation_policy(source.reputation)
            if rep_rate is not None: meter_candidates.append((rep_rate, "m3"))
        meter, meter_source = min(meter_candidates, key=lambda pair: pair[0]) if meter_candidates else (None, None)
        if not path and not drop_reason: drop_reason = "NO_ROUTE"
        if drop_reason is None and meter:
            # Keep independent policy budgets: an unrelated unmetered packet
            # must not reset a flood meter or replenish a shared M3 source cap.
            budgets = []
            meter_buckets = source.meter_buckets if source else self.rsu_meter_buckets[src]
            for rate, owner in meter_candidates:
                scope = (owner, rule["id"] if owner == "m1" else owner)
                capacity = max(2048, rate * 125 * .25)
                bucket = meter_buckets.get(scope)
                if bucket is None:
                    bucket = {"tokens": capacity, "rate": rate, "at": self.t}
                    meter_buckets[scope] = bucket
                else:
                    bucket["tokens"] = min(capacity, bucket["tokens"] +
                        bucket["rate"] * 125 * max(0, self.t - bucket["at"]))
                    bucket["rate"], bucket["at"] = rate, self.t
                budgets.append((bucket, owner))
            exhausted = [(bucket, owner) for bucket, owner in budgets
                         if bucket["tokens"] + 1e-9 < size]
            if exhausted:
                drop_reason = "RATE_LIMIT"
                self.totals[f"{exhausted[0][1]}_meter_drops"] += 1
            else:
                for bucket, owner in budgets:
                    bucket["tokens"] -= size
        if drop_reason is None and radio_lost:
            drop_reason = "RADIO_LOSS"
        if drop_reason is None and link in ("V2I", "I2V"):
            gateway = source.rsu if source else src
            if gateway in self.rsu_tokens:
                if self.rsu_tokens[gateway] < size:
                    drop_reason = "RSU_CONGESTION"
                else:
                    self.rsu_tokens[gateway] -= size
        self._record_packet(src, dst, traffic, size, drop_reason is None, drop_reason or "FORWARDED",
                            path, link, meter)
        return drop_reason is None

    def _tick_vehicle(self, v: Vehicle, dt: float):
        v.safety_acc += dt * 2
        v.data_acc += dt * 1.3
        safety_events = min(int(v.safety_acc), 10)
        data_events = min(int(v.data_acc), 10)
        v.safety_acc -= safety_events
        v.data_acc -= data_events
        is_bad = v.id == self.attacker and self.scenario in ("misinformation", "combined")
        for sample_i in range(safety_events):
            sample_at = self.t - min(dt * .75, (safety_events - 1 - sample_i) * .5)
            self._send_safety(v, is_bad, sample_at)
        for _ in range(data_events):
            if v.rsu: self._send(v.id, v.rsu, "TELEMETRY", 420)
        if v.id == self.attacker and self.scenario in ("flood", "combined"):
            v.flood_acc += self.config["flood_pps"] * dt
            count = min(int(v.flood_acc), 200)
            v.flood_acc -= count
            for _ in range(count): self._send(v.id, self.victim, "UDP_FLOOD", 1024)

    def step(self, dt: float = .1):
        with self.lock:
            if not self.running: return
            if not math.isfinite(dt) or dt <= 0:
                raise ValueError("Step duration must be positive and finite")
            remaining = min(dt, .25) * self.speed_factor
            while remaining > 1e-9:
                substep = min(.1, remaining)
                self._step(substep)
                remaining -= substep

    def _step(self, dt):
        with self.lock:
            self.t += dt
            self.tick_index += 1
            self._move(dt)
            for v in self.vehicles.values():
                while v.tx_times and v.tx_times[0] < self.t - self.config['m2_window_sec']:
                    v.tx_times.popleft()
                self._detect_attack(v)
            for r in self.rsus:
                rid = r["id"]
                capacity = self.config["rsu_backhaul_mbps"] * 125000
                self.rsu_tokens[rid] = min(capacity * .25, self.rsu_tokens[rid] + capacity * dt)
            for v in self.vehicles.values():
                self._tick_vehicle(v, dt)
            # Simulated infrastructure-to-vehicle beacons, approximately 1 Hz.
            if int((self.t - dt)) < int(self.t):
                for r in self.rsus:
                    attached = [v for v in self.vehicles.values() if v.rsu == r["id"]]
                    if attached:
                        self._send(r["id"], attached[0].id, "BEACON", 100)
            self._history_acc += dt
            if self._history_acc >= 1.0:
                self._history_acc -= 1
                self._snapshot_history()

    def _window(self, interval: float = 10.0) -> tuple[int, int, int, int]:
        cutoff = self.t - interval
        while self.outcomes and self.outcomes[0][0] < cutoff:
            self.outcomes.popleft()
        sent = len(self.outcomes)
        delivered = sum(bool(x[1]) for x in self.outcomes)
        legitimate = [x for x in self.outcomes if not x[2]]
        legit_ok = sum(bool(x[1]) for x in legitimate)
        return sent, delivered, len(legitimate), legit_ok

    def _snapshot_history(self):
        sent, delivered, leg_total, leg_ok = self._window()
        self.history.append({"t": round(self.t), "pps": round(sent / min(10.0, max(self.t, 1))),
                             "delivered": round(delivered / min(10.0, max(self.t, 1))),
                             "dropped": round((sent - delivered) / min(10.0, max(self.t, 1))),
                             "legit_pdr": round(100 * leg_ok / leg_total, 1) if leg_total else 100})

    def status(self) -> dict:
        with self.lock:
            sent, delivered, legit_total, legit_ok = self._window()
            all_sent = self.totals["sent"]
            all_delivered = self.totals["delivered"]
            active = sum((self.config["m2_enabled"] and v.m2_stage in ("METER", "BLOCK")) or
                         (self.config["m3_enabled"] and reputation_policy(v.reputation)[0] is not None)
                         for v in self.vehicles.values())
            runtime_policies = []
            for v in self.vehicles.values():
                static = self._matching_static_rule(v.id, "UDP_FLOOD", v.rsu)
                rate, trust_state = reputation_policy(v.reputation)
                m2_state = v.m2_stage if self.config["m2_enabled"] else "DISABLED"
                monitored = self._m2_matches(v, self.victim, 'UDP_FLOOD')
                caps = ([static["rate_kbps"]] if static and static["action"] == "METER" else [])
                if monitored and m2_state == "METER": caps.append(self.config["m2_meter_kbps"])
                if rate and self.config["m3_enabled"]: caps.append(rate)
                effective_drop = bool(static and static["action"] == "DROP") or (monitored and m2_state == "BLOCK")
                if static or m2_state in ("METER", "BLOCK") or (rate and self.config["m3_enabled"]):
                    runtime_policies.append({"vehicle": v.id, "rsu": v.rsu,
                                             "static_action": static["action"] if static else None,
                                             "static_rule_id": static["id"] if static else None,
                                             "m2_state": m2_state,
                                             "m3_state": trust_state if self.config["m3_enabled"] else "DISABLED",
                                             "m3_meter_kbps": rate if self.config["m3_enabled"] else None,
                                             "effective_udp_action": "DROP" if effective_drop else "METER" if caps else "ALLOW",
                                             "effective_udp_destination": self.victim,
                                             "effective_udp_meter_kbps": None if effective_drop or not caps else min(caps)})
            now = self.t
            return {
                "time": round(now, 2), "running": self.running, "speed_factor": self.speed_factor,
                "scenario": self.scenario, "attacker": self.attacker, "victim": self.victim,
                "mobility_mode": self.mobility_mode,
                "vehicles": [v.snapshot(now, self._threshold(v), self.config["m3_enabled"]) for v in self.vehicles.values()],
                "rsus": [dict(r, vehicles=sum(1 for v in self.vehicles.values() if v.rsu == r["id"])) for r in self.rsus],
                "pulses": [p for p in self.pulses if now - p["t"] <= 3],
                "runtime_policies": runtime_policies,
                "events": list(self.events)[:65], "rules": deepcopy(self.rules), "config": deepcopy(self.config),
                "history": list(self.history)[-60:],
                "reasons": dict(self.reasons),
                "stats": {"sent": all_sent, "delivered": all_delivered,
                          "dropped": all_sent - all_delivered,
                          "pdr": round(100 * all_delivered / all_sent, 1) if all_sent else 100,
                          "legit_pdr": round(100 * legit_ok / legit_total, 1) if legit_total else 100,
                          "pps": round(sent / min(10.0, max(now, 1))),
                          "recent_drops": sent - delivered, "handovers": self.totals["handovers"],
                          "invalid_safety": self.totals["invalid_safety"],
                          "observed_safety": self.totals['observed_safety'],
                          "rejected_safety": self.totals['rejected_safety'],
                          "m2_blocks": self.totals["m2_blocks"],
                          "enforced_vehicles": active,
                          "rate_limited": self.reasons["RATE_LIMIT"],
                          "m1_meter_drops": self.totals["m1_meter_drops"],
                          "m2_meter_drops": self.totals["m2_meter_drops"],
                          "m3_meter_drops": self.totals["m3_meter_drops"],
                          "m1_dropped": self.reasons["M1_STATIC_DROP"],
                          "m2_dropped": self.reasons["M2_TEMP_BLOCK"],
                          "attack_sent": self.totals["attack_sent"],
                          "attack_delivered": self.totals["attack_delivered"],
                          "legitimate_sent": self.totals["legitimate_sent"],
                          "legitimate_delivered": self.totals["legitimate_delivered"]},
                "note": "Discrete-event SDN/VANET simulation; no physical radios, Ryu or OVS are running.",
            }

    def set_scenario(self, scenario: str, attacker: str | None = None, victim: str | None = None):
        with self.lock:
            if scenario not in ("normal", "flood", "misinformation", "combined"):
                raise ValueError("Scenario must be normal, flood, misinformation or combined")
            new_attacker = self.attacker if attacker is None else attacker
            new_victim = self.victim if victim is None else victim
            if not isinstance(new_attacker, str) or new_attacker not in self.vehicles:
                raise ValueError("Unknown attacker vehicle")
            if not isinstance(new_victim, str) or new_victim not in self.vehicles:
                raise ValueError("Unknown victim vehicle")
            if new_attacker == new_victim: raise ValueError("Attacker and victim must differ")
            self.attacker, self.victim = new_attacker, new_victim
            self.scenario = scenario
            self._event("SCENARIO", {
                "normal": "Normal traffic restored; outstanding dynamic policies recover by policy",
                "flood": f"UDP flood started: {self.attacker} → {self.victim}",
                "misinformation": f"False safety reports started: {self.attacker}",
                "combined": f"Combined UDP flood + false safety reports: {self.attacker}",
            }[scenario], "danger" if scenario != "normal" else "success")
            return self.status()

    def set_running(self, running: bool):
        with self.lock:
            self.running = bool(running)
            self._event("SYSTEM", "Simulation resumed" if running else "Simulation paused")
            return self.status()

    def set_speed(self, factor: float):
        with self.lock:
            if factor not in (0.5, 1, 2, 4): raise ValueError("Speed must be 0.5, 1, 2, or 4")
            self.speed_factor = factor
            return self.status()

    def reset(self):
        with self.lock:
            cfg, rules, next_rule = deepcopy(self.config), deepcopy(self.rules), self.next_rule
            old_mode = self.mobility_mode
            if self.sumo_bridge: self.sumo_bridge.close()
            fresh = SimEngine(seed=self.seed)
            fresh.set_config(cfg)
            fresh._associate(initial=True)
            fresh.rsu_tokens = {r["id"]: cfg["rsu_backhaul_mbps"] * 125000 * .25
                                for r in fresh.rsus}
            for attr in ("running", "speed_factor", "t", "tick_index", "scenario", "attacker",
                         "victim", "vehicles", "rsus", "rsu_tokens", "events", "pulses", "history",
                         "outcomes", "totals", "reasons", "_history_acc", "rng", "visual_rng",
                         "rsu_meter_buckets", "handover_times", "m2_config"):
                setattr(self, attr, getattr(fresh, attr))
            self.config, self.rules, self.next_rule = cfg, rules, next_rule
            self.mobility_mode, self.sumo_bridge = "builtin", None
            if old_mode == "sumo":
                # Retain safe fallback if SUMO is unavailable on restart.
                try: self.set_mobility_mode("sumo")
                except ValueError: self._event("MOBILITY", "SUMO restart failed; using built-in trajectories", "warning")
            return self.status()

    def set_mobility_mode(self, mode: str):
        with self.lock:
            if mode not in ("builtin", "sumo"):
                raise ValueError("Mode must be builtin or sumo")
            if self.mobility_mode == mode: return self.status()
            provider = None
            if mode == "sumo":
                from sumo_tools import SumoBridge
                provider = SumoBridge()
                provider.start()  # Validates native SUMO/TraCI before modifying state.
            if self.sumo_bridge: self.sumo_bridge.close()
            # Reset counters on mobility-engine changes: mixing runs is misleading.
            cfg, rules, next_rule = deepcopy(self.config), deepcopy(self.rules), self.next_rule
            fresh = SimEngine(seed=self.seed)
            fresh.set_config(cfg)
            fresh._associate(initial=True)
            fresh.rsu_tokens = {r["id"]: cfg["rsu_backhaul_mbps"] * 125000 * .25
                                for r in fresh.rsus}
            for attr in ("running", "speed_factor", "t", "tick_index", "scenario", "attacker",
                         "victim", "vehicles", "rsus", "rsu_tokens", "events", "pulses", "history",
                         "outcomes", "totals", "reasons", "_history_acc", "rng", "visual_rng",
                         "rsu_meter_buckets", "handover_times", "m2_config"):
                setattr(self, attr, getattr(fresh, attr))
            self.config, self.rules, self.next_rule = cfg, rules, next_rule
            self.mobility_mode, self.sumo_bridge = mode, provider
            self._event("MOBILITY", "Native SUMO TraCI mobility enabled; experiment reset" if mode == "sumo"
                        else "Built-in road mobility enabled; experiment reset", "success")
            return self.status()

    def set_config(self, changes: dict):
        with self.lock:
            allowed = {
                "base_pps": (int, 20, 800), "flood_pps": (int, 50, 800),
                "stage2_after_sec": (float, 1, 30), "block_duration_sec": (float, 1, 120),
                "m2_meter_kbps": (int, 50, 10000), "radio_range": (int, 50, 350),
                "m2_window_sec": (float, 1, 30), "m2_meter_lifetime_sec": (float, 2, 120),
                "m2_reset_sec": (float, 1, 120), "dense_pps": (int, 20, 800),
                "sparse_pps": (int, 20, 800), "handover_floor_pps": (int, 20, 800),
                "rsu_range": (int, 130, 500), "rsu_backhaul_mbps": (float, .25, 50),
                "max_reported_speed_kmh": (int, 40, 300),
                "max_acceleration_mps2": (float, .1, 50), "position_tolerance_m": (float, 0, 100),
                "reputation_penalty": (float, .01, .5), "recovery_every": (int, 1, 50),
                "recovery_gain": (float, .005, .2), "loss_probability": (float, 0, .3),
            }
            validated = {}
            for name, value in changes.items():
                if name in ("m1_enabled", "m2_enabled", "m3_enabled"):
                    if not isinstance(value, bool): raise ValueError(f"{name} requires true/false")
                elif name == 'm2_monitored_rsu':
                    if value not in ('*', 'RSU-1', 'RSU-2', 'RSU-3'):
                        raise ValueError('m2_monitored_rsu must be * or an RSU ID')
                else:
                    if name not in allowed: raise ValueError(f"Unknown configuration: {name}")
                    typ, lo, hi = allowed[name]
                    if not isinstance(value, (int, float)) or isinstance(value, bool) or not lo <= value <= hi:
                        raise ValueError(f"{name} must be between {lo} and {hi}")
                    value = typ(value)
                validated[name] = value
            proposed = dict(self.config, **validated)
            if proposed['m2_meter_lifetime_sec'] <= proposed['stage2_after_sec']:
                raise ValueError('M2 flow lifetime must exceed Stage 1 dwell')
            self.config.update(validated)
            self.m2_config = detector_config(self.config)
            for v in self.vehicles.values():
                if not self.config["m2_enabled"]:
                    self._reset_m2(v, 'M2 disabled')
                if not self.config["m3_enabled"]:
                    v.meter_buckets.pop(("m3", "m3"), None)
            for name, value in validated.items():
                self._event("POLICY", f"Controller setting {name} = {value}", "info")
            return self.status()

    @staticmethod
    def _validated_rule(data: dict, rule_id: str) -> dict:
        try:
            priority = int(data.get("priority", 500))
            source = str(data.get("source", "*"))
            traffic = str(data.get("traffic", "*"))
            rsu = str(data.get("rsu", "*"))
            action = str(data.get("action", "DROP"))
            enabled = data.get("enabled", True)
            label = str(data.get("label", "Custom rule"))[:80].strip()
            raw_rate = data.get("rate_kbps", 500)
            kbps = int(raw_rate) if action == "METER" else None
        except (TypeError, ValueError, OverflowError):
            raise ValueError("Invalid rule fields") from None
        if not 1 <= priority <= 999: raise ValueError("Priority must be 1–999")
        if source != "*" and source not in {f"V{i:02}" for i in range(1, 13)} | {r["id"] for r in RSUS}:
            raise ValueError("Unknown source")
        if traffic not in ("*", "SAFETY", "TELEMETRY", "UDP_FLOOD", "BEACON"):
            raise ValueError("Invalid traffic type")
        if rsu not in ("*", "RSU-1", "RSU-2", "RSU-3"):
            raise ValueError("Invalid RSU")
        if action not in ("DROP", "METER", "ALLOW"): raise ValueError("Invalid action")
        if type(enabled) is not bool: raise ValueError("Enabled must be true/false")
        if action == "METER" and not 10 <= kbps <= 50000: raise ValueError("Rate must be 10–50000 kbps")
        return {"id": rule_id, "priority": priority, "source": source, "traffic": traffic,
                "rsu": rsu, "action": action, "rate_kbps": kbps, "enabled": enabled,
                "label": label or "Custom rule"}

    def upsert_rule(self, data: dict, rule_id: str | None = None):
        with self.lock:
            if rule_id is not None and not any(r["id"] == rule_id for r in self.rules):
                raise ValueError("Rule not found")
            if rule_id is None:
                if len(self.rules) >= 100: raise ValueError("100 rules maximum")
                rule_id = f"rule-{self.next_rule}"
                creating = True
            else:
                creating = False
            rule = self._validated_rule(data, rule_id)
            if creating: self.next_rule += 1
            self.rules = [r for r in self.rules if r["id"] != rule_id] + [rule]
            self._event("M1 · RULE", f"{'Enabled' if rule['enabled'] else 'Saved'}: {rule['label']} ({rule['action']})", "warning")
            return self.status()

    def delete_rule(self, rule_id: str):
        with self.lock:
            if not any(r["id"] == rule_id for r in self.rules): raise ValueError("Rule not found")
            self.rules = [r for r in self.rules if r["id"] != rule_id]
            for buckets in [v.meter_buckets for v in self.vehicles.values()] + list(self.rsu_meter_buckets.values()):
                buckets.pop(("m1", rule_id), None)
            self._event("M1 · RULE", f"Removed static rule {rule_id}", "info")
            return self.status()

    def simulation_report(self) -> dict:
        with self.lock:
            return {"metadata": {"project": "MarsVanet Visual Unified", "mode": "simulation",
                                  "policy_implementation": "original_pure_python_helpers_v1",
                                  "m2_scope": {"victim": self.victim,
                                               "ingress_rsu": self.config['m2_monitored_rsu'],
                                               "source_state": "per_vehicle_across_handover",
                                               "rate_evidence": "simulated ingress events and one-second counter deltas"},
                                  "m3_speed_unit": "m/s in safety payload; km/h in UI",
                                  "seed": self.seed, "attack_metric_scope": "UDP_FLOOD packets only",
                                  "time": round(self.t, 3), "scenario": self.scenario,
                                  "mobility_mode": self.mobility_mode},
                    "config": deepcopy(self.config), "rules": deepcopy(self.rules),
                    "summary": self.status()["stats"], "reasons": dict(self.reasons),
                    "history": list(self.history), "events": list(reversed(self.events))}
