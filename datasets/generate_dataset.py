"""Generate a production-style synthetic cloud attack dataset for ML experiments."""

from __future__ import annotations

import random
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Tuple

import pandas as pd


NUM_ROWS = 10000
RANDOM_SEED = 42
OUTPUT_FILE = Path(__file__).resolve().parent / "synthetic_attack_dataset.csv"

RISK_LEVEL_BOUNDS: Dict[str, Tuple[int, int]] = {
    "LOW": (0, 34),
    "MEDIUM": (35, 69),
    "HIGH": (70, 100),
}

TARGET_RISK_LEVEL_WEIGHTS: Dict[str, float] = {
    "LOW": 0.25,
    "MEDIUM": 0.40,
    "HIGH": 0.35,
}

ASSET_TYPES = ["VM", "Database", "Bucket", "IAM Role", "Container", "Load Balancer"]
ASSET_WEIGHTS = [0.24, 0.16, 0.18, 0.12, 0.18, 0.12]


@dataclass(frozen=True)
class AssetProfile:
    """Baseline risk-relevant properties for each cloud asset type."""

    internet_exposed_p: float
    public_access_p: float
    critical_data_p: float
    weak_iam_p: float
    open_port_range: Tuple[int, int]
    vulnerability_range: Tuple[int, int]
    critical_vuln_ratio_range: Tuple[float, float]
    misconfiguration_range: Tuple[int, int]
    lateral_movement_base_p: float
    privilege_escalation_base_p: float


ASSET_PROFILES: Dict[str, AssetProfile] = {
    # VM: often internet-facing, moderate to high vulnerability surface, moderate movement risk.
    "VM": AssetProfile(0.64, 0.15, 0.44, 0.24, (2, 16), (3, 16), (0.20, 0.48), (1, 7), 0.30, 0.24),
    # Database: usually internal, often stores critical data; exposure has high consequence.
    "Database": AssetProfile(0.16, 0.06, 0.88, 0.20, (0, 6), (2, 12), (0.18, 0.42), (0, 6), 0.16, 0.15),
    # Bucket: low port footprint but public access and misconfiguration can be impactful.
    "Bucket": AssetProfile(0.42, 0.33, 0.58, 0.18, (0, 3), (0, 7), (0.12, 0.34), (1, 8), 0.18, 0.18),
    # IAM Role: low network exposure, high identity/permission risk.
    "IAM Role": AssetProfile(0.04, 0.02, 0.40, 0.43, (0, 1), (0, 4), (0.16, 0.40), (0, 6), 0.26, 0.40),
    # Container: moderate exposure, moderate vulnerabilities, lateral movement commonly relevant.
    "Container": AssetProfile(0.55, 0.13, 0.38, 0.27, (1, 12), (2, 15), (0.20, 0.44), (1, 8), 0.35, 0.26),
    # Load Balancer: often internet-facing and can expose downstream attack opportunities.
    "Load Balancer": AssetProfile(0.82, 0.09, 0.24, 0.13, (1, 10), (1, 9), (0.14, 0.34), (1, 6), 0.22, 0.20),
}

BAND_ADJUSTMENTS: Dict[str, Dict[str, float]] = {
    "LOW": {"p": -0.18, "count": -0.34},
    "MEDIUM": {"p": 0.00, "count": 0.00},
    "HIGH": {"p": 0.22, "count": 0.46},
}

RISK_LEVELS = ["LOW", "MEDIUM", "HIGH"]


def clamp(value: float, low: float, high: float) -> float:
    """Clamp a numeric value between low and high."""

    return max(low, min(high, value))


def to_binary(probability: float, rng: random.Random) -> int:
    """Sample a 0/1 value from a probability."""

    return 1 if rng.random() < clamp(probability, 0.0, 1.0) else 0


def risk_level_from_score(score: float) -> str:
    """Map a risk score to its categorical risk level."""

    for level, (lower, upper) in RISK_LEVEL_BOUNDS.items():
        if lower <= score <= upper:
            return level
    return "HIGH"


def adjusted_count(
    base_range: Tuple[int, int],
    band: str,
    rng: random.Random,
    floor: int = 0,
    cap: int | None = None,
) -> int:
    """Generate a count from a range with risk-band driven adjustment."""

    low, high = base_range
    base_value = rng.randint(low, high)
    span = max(1, high - low)
    delta = int(round(BAND_ADJUSTMENTS[band]["count"] * span))
    value = base_value + delta + rng.randint(-1, 1)
    if cap is None:
        return max(floor, value)
    return int(clamp(value, floor, cap))


def choose_asset_type(rng: random.Random) -> str:
    """Select an asset type with realistic frequency."""

    return rng.choices(ASSET_TYPES, weights=ASSET_WEIGHTS, k=1)[0]


def compute_attack_path_count(
    asset_type: str,
    vulnerability_count: int,
    critical_vulnerability_count: int,
    misconfiguration_count: int,
    weak_iam: int,
    lateral_movement_possible: int,
    privilege_escalation_possible: int,
    internet_exposed: int,
    public_access: int,
    band: str,
    rng: random.Random,
) -> int:
    """Estimate attack path count from structural weaknesses and exposure."""

    signal = (
        0.26 * vulnerability_count
        + 0.90 * critical_vulnerability_count
        + 0.42 * misconfiguration_count
        + 1.7 * weak_iam
        + 2.0 * lateral_movement_possible
        + 2.1 * privilege_escalation_possible
        + 1.5 * internet_exposed
        + 1.9 * public_access
    )

    asset_multiplier = {
        "VM": 1.10,
        "Database": 0.95,
        "Bucket": 0.90,
        "IAM Role": 0.82,
        "Container": 1.06,
        "Load Balancer": 1.00,
    }[asset_type]
    signal *= asset_multiplier

    # Asset-specific realism boosts for high-risk cloud patterns.
    if asset_type == "Bucket" and public_access:
        signal += 2.6
    if asset_type == "Database" and internet_exposed:
        signal += 2.4
    if asset_type == "IAM Role" and weak_iam:
        signal += 2.5
    if asset_type == "Load Balancer" and internet_exposed:
        signal += 1.4
    if asset_type == "VM" and internet_exposed and critical_vulnerability_count >= 3:
        signal += 2.2

    signal *= 0.85 if band == "LOW" else 1.0
    signal *= 1.18 if band == "HIGH" else 1.0

    jitter = rng.uniform(-1.2, 1.2)
    value = int(round(signal + jitter))
    return int(clamp(value, 0, 24))


def compute_shortest_path_length(attack_path_count: int, band: str, rng: random.Random) -> int:
    """Return shortest attack path length.

    A value of 0 explicitly means no valid attack path exists.
    If at least one attack path exists, minimum valid length is 1.
    """

    if attack_path_count == 0:
        return 0

    if band == "HIGH":
        value = rng.randint(1, 4)
    elif band == "MEDIUM":
        value = rng.randint(2, 6)
    else:
        value = rng.randint(4, 9)

    # More available paths usually include at least one short route.
    if attack_path_count >= 8:
        value = max(1, value - 1)
    return value


def compute_component_scores(
    row: Dict[str, int | str],
) -> Tuple[float, float, float]:
    """Compute normalized exposure, identity, and network risk subscores."""

    open_port_factor = min(row["open_port_count"] / 20, 1.0)
    vuln_factor = min(row["vulnerability_count"] / 24, 1.0)
    critical_vuln_factor = min(row["critical_vulnerability_count"] / 8, 1.0)
    misconfig_factor = min(row["misconfiguration_count"] / 12, 1.0)
    path_factor = min(row["attack_path_count"] / 18, 1.0)

    if row["attack_path_count"] == 0 or row["shortest_path_length"] == 0:
        shortest_path_factor = 0.0
    else:
        shortest_path_factor = 1 - min((row["shortest_path_length"] - 1) / 8, 1.0)

    exposure_score = (
        34 * row["internet_exposed"]
        + 26 * row["public_access"]
        + 14 * open_port_factor
        + 9 * vuln_factor
        + 10 * path_factor
        + 7 * shortest_path_factor
    )

    identity_risk_score = (
        38 * row["weak_iam"]
        + 28 * row["privilege_escalation_possible"]
        + 18 * row["lateral_movement_possible"]
        + 18 * row["has_critical_data"]
    )

    network_risk_score = (
        24 * open_port_factor
        + 18 * misconfig_factor
        + 18 * path_factor
        + 12 * shortest_path_factor
        + 14 * row["internet_exposed"]
        + 14 * row["public_access"]
    )

    asset_type = str(row["asset_type"])
    if asset_type == "Bucket" and row["public_access"]:
        exposure_score += 16
        network_risk_score += 10
    if asset_type == "Database" and row["internet_exposed"]:
        exposure_score += 12
        network_risk_score += 8
    if asset_type == "IAM Role" and row["weak_iam"]:
        identity_risk_score += 18
    if asset_type == "Load Balancer" and row["internet_exposed"]:
        exposure_score += 8
        network_risk_score += 8
    if asset_type == "VM" and row["internet_exposed"] and row["critical_vulnerability_count"] >= 3:
        exposure_score += 8
        network_risk_score += 6

    return (
        clamp(exposure_score, 0, 100),
        clamp(identity_risk_score, 0, 100),
        clamp(network_risk_score, 0, 100),
    )


def compute_risk_score(
    exposure_score: float,
    identity_risk_score: float,
    network_risk_score: float,
    row: Dict[str, int | str],
    rng: random.Random,
) -> float:
    """Compute weighted final risk score bounded to 0..100."""

    critical_vuln_factor = min(row["critical_vulnerability_count"] / 8, 1.0)
    path_factor = min(row["attack_path_count"] / 18, 1.0)
    vuln_factor = min(row["vulnerability_count"] / 24, 1.0)
    misconfig_factor = min(row["misconfiguration_count"] / 12, 1.0)

    if row["attack_path_count"] == 0 or row["shortest_path_length"] == 0:
        shortest_path_pressure = 0.0
    else:
        shortest_path_pressure = 1 - min((row["shortest_path_length"] - 1) / 9, 1.0)

    # If there is no attack path, penalize final score to keep realistic posture.
    no_path_penalty = 0.76 if row["attack_path_count"] == 0 else 1.0

    raw_score = (
        0.27 * exposure_score
        + 0.24 * identity_risk_score
        + 0.22 * network_risk_score
        + 10.5 * critical_vuln_factor
        + 7.0 * path_factor
        + 4.8 * vuln_factor
        + 4.0 * misconfig_factor
        + 4.8 * shortest_path_pressure
        + 3.0 * row["has_critical_data"]
    )

    asset_type = str(row["asset_type"])
    if asset_type == "Bucket" and row["public_access"]:
        raw_score += 8.0
    if asset_type == "Database" and row["internet_exposed"]:
        raw_score += 8.0
    if asset_type == "IAM Role" and row["weak_iam"]:
        raw_score += 8.5
    if asset_type == "Load Balancer" and row["internet_exposed"]:
        raw_score += 4.5
    if asset_type == "VM" and row["internet_exposed"] and row["critical_vulnerability_count"] >= 3:
        raw_score += 5.5

    if (
        row["internet_exposed"] == 0
        and row["public_access"] == 0
        and row["vulnerability_count"] <= 2
        and row["misconfiguration_count"] <= 1
        and row["privilege_escalation_possible"] == 0
        and row["lateral_movement_possible"] == 0
    ):
        raw_score -= 9.0

    jitter = rng.uniform(-2.2, 2.2)
    return clamp((raw_score + jitter) * no_path_penalty, 0, 100)


def generate_scenario(target_level: str, scenario_index: int, rng: random.Random) -> Dict[str, int | float | str]:
    """Generate one scenario aligned to a target risk level using rule-based logic."""

    asset_type = choose_asset_type(rng)
    profile = ASSET_PROFILES[asset_type]
    band_delta = BAND_ADJUSTMENTS[target_level]["p"]

    internet_exposed = to_binary(profile.internet_exposed_p + band_delta, rng)
    public_boost = 0.12 if internet_exposed else -0.06
    if asset_type == "Bucket":
        public_boost += 0.12
    elif asset_type == "Database":
        public_boost -= 0.05
    elif asset_type == "IAM Role":
        public_boost -= 0.07
    public_access = to_binary(profile.public_access_p + band_delta + public_boost, rng)
    has_critical_data = to_binary(profile.critical_data_p + 0.55 * band_delta, rng)
    weak_iam_boost = 0.08 if asset_type == "IAM Role" else 0.0
    weak_iam = to_binary(profile.weak_iam_p + band_delta + weak_iam_boost, rng)

    vulnerability_count = adjusted_count(profile.vulnerability_range, target_level, rng, floor=0, cap=30)

    ratio_low, ratio_high = profile.critical_vuln_ratio_range
    ratio = rng.uniform(ratio_low, ratio_high)
    ratio += 0.08 if target_level == "HIGH" else 0.0
    ratio -= 0.07 if target_level == "LOW" else 0.0
    ratio = clamp(ratio, 0.0, 0.70)
    critical_vulnerability_count = int(round(vulnerability_count * ratio))
    critical_vulnerability_count = int(clamp(critical_vulnerability_count + rng.randint(-1, 1), 0, min(12, vulnerability_count)))

    misconfiguration_count = adjusted_count(profile.misconfiguration_range, target_level, rng, floor=0, cap=12)
    open_port_count = adjusted_count(profile.open_port_range, target_level, rng, floor=0, cap=25)

    lateral_movement_p = (
        profile.lateral_movement_base_p
        + 0.23 * weak_iam
        + 0.025 * min(vulnerability_count, 14)
        + (0.16 if target_level == "HIGH" else 0.0)
        - (0.09 if target_level == "LOW" else 0.0)
    )
    lateral_movement_possible = to_binary(lateral_movement_p, rng)

    privilege_escalation_p = (
        profile.privilege_escalation_base_p
        + 0.25 * weak_iam
        + 0.05 * min(critical_vulnerability_count, 6)
        + (0.15 if target_level == "HIGH" else 0.0)
        - (0.09 if target_level == "LOW" else 0.0)
    )
    privilege_escalation_possible = to_binary(privilege_escalation_p, rng)

    attack_path_count = compute_attack_path_count(
        asset_type,
        vulnerability_count,
        critical_vulnerability_count,
        misconfiguration_count,
        weak_iam,
        lateral_movement_possible,
        privilege_escalation_possible,
        internet_exposed,
        public_access,
        target_level,
        rng,
    )
    shortest_path_length = compute_shortest_path_length(attack_path_count, target_level, rng)

    row: Dict[str, int | float | str] = {
        "scenario_id": f"SCN-{scenario_index:05d}",
        "asset_type": asset_type,
        "internet_exposed": internet_exposed,
        "public_access": public_access,
        "has_critical_data": has_critical_data,
        "weak_iam": weak_iam,
        "lateral_movement_possible": lateral_movement_possible,
        "privilege_escalation_possible": privilege_escalation_possible,
        "open_port_count": open_port_count,
        "vulnerability_count": vulnerability_count,
        "critical_vulnerability_count": min(critical_vulnerability_count, vulnerability_count),
        "misconfiguration_count": misconfiguration_count,
        "attack_path_count": attack_path_count,
        "shortest_path_length": shortest_path_length,
    }

    exposure_score, identity_risk_score, network_risk_score = compute_component_scores(row)
    risk_score = compute_risk_score(exposure_score, identity_risk_score, network_risk_score, row, rng)

    row["exposure_score"] = round(exposure_score, 2)
    row["identity_risk_score"] = round(identity_risk_score, 2)
    row["network_risk_score"] = round(network_risk_score, 2)
    row["risk_score"] = round(risk_score, 2)
    row["risk_level"] = risk_level_from_score(float(row["risk_score"]))

    return row


def generate_dataset(row_count: int = NUM_ROWS, seed: int = RANDOM_SEED) -> pd.DataFrame:
    """Generate full synthetic dataset with realistic and balanced distributions."""

    rng = random.Random(seed)

    target_levels: List[str] = rng.choices(
        RISK_LEVELS,
        weights=[TARGET_RISK_LEVEL_WEIGHTS[level] for level in RISK_LEVELS],
        k=row_count,
    )

    scenarios: List[Dict[str, int | float | str]] = []
    for index, target_level in enumerate(target_levels, start=1):
        candidate = generate_scenario(target_level, index, rng)
        scenarios.append(candidate)

    dataset = pd.DataFrame(scenarios)

    ordered_columns = [
        "scenario_id",
        "asset_type",
        "internet_exposed",
        "public_access",
        "has_critical_data",
        "weak_iam",
        "lateral_movement_possible",
        "privilege_escalation_possible",
        "open_port_count",
        "vulnerability_count",
        "critical_vulnerability_count",
        "misconfiguration_count",
        "attack_path_count",
        "shortest_path_length",
        "exposure_score",
        "identity_risk_score",
        "network_risk_score",
        "risk_score",
        "risk_level",
    ]

    return dataset[ordered_columns]


def print_summary(dataset: pd.DataFrame) -> None:
    """Print generation summary required for quick verification."""

    print(f"Total rows generated: {len(dataset)}")
    print("\nRisk level distribution:")
    risk_counts = dataset["risk_level"].value_counts().reindex(RISK_LEVELS, fill_value=0)
    print(risk_counts)
    print("\nRisk level percentages:")
    print((risk_counts / len(dataset) * 100).round(2))

    print("\nAsset type distribution:")
    asset_counts = dataset["asset_type"].value_counts().reindex(ASSET_TYPES, fill_value=0)
    print(asset_counts)
    print("\nAsset type percentages:")
    print((asset_counts / len(dataset) * 100).round(2))


def main() -> None:
    """Generate, save, and summarize synthetic cloud attack dataset."""

    random.seed(RANDOM_SEED)
    dataset = generate_dataset(row_count=NUM_ROWS, seed=RANDOM_SEED)
    dataset.to_csv(OUTPUT_FILE, index=False)
    print(f"CSV save path: {OUTPUT_FILE}")
    print_summary(dataset)


if __name__ == "__main__":
    main()
