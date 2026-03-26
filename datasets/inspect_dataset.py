"""Inspect and validate synthetic attack dataset quality and constraints."""

from __future__ import annotations

from pathlib import Path
from typing import Iterable, List

import pandas as pd


DATASET_FILE = Path(__file__).resolve().parent / "synthetic_attack_dataset.csv"
VALID_RISK_LEVELS = {"LOW", "MEDIUM", "HIGH"}

COUNT_COLUMNS = [
    "open_port_count",
    "vulnerability_count",
    "critical_vulnerability_count",
    "misconfiguration_count",
    "attack_path_count",
    "shortest_path_length",
]

IMPORTANT_COLUMNS = [
    "exposure_score",
    "critical_vulnerability_count",
    "vulnerability_count",
    "attack_path_count",
    "shortest_path_length",
]

PERCENT_SCALE = 100.0


def load_dataset(path: Path = DATASET_FILE) -> pd.DataFrame:
    """Load the synthetic dataset from CSV with clear error reporting."""

    if not path.exists():
        raise FileNotFoundError(f"Dataset file not found: {path}")
    return pd.read_csv(path)


def print_basic_summary(dataset: pd.DataFrame) -> None:
    """Print basic dataset statistics for quick inspection."""

    print(f"Dataset shape: {dataset.shape}")
    print("\nMissing values per column:")
    print(dataset.isna().sum())

    print("\nRisk level counts:")
    risk_counts = dataset["risk_level"].value_counts().sort_index()
    print(risk_counts)
    print("\nRisk level percentages:")
    print((risk_counts / len(dataset) * PERCENT_SCALE).round(2))

    print("\nAsset type counts:")
    asset_counts = dataset["asset_type"].value_counts()
    print(asset_counts)
    print("\nAsset type percentages:")
    print((asset_counts / len(dataset) * PERCENT_SCALE).round(2))


def print_numeric_statistics(dataset: pd.DataFrame) -> None:
    """Print descriptive statistics for numeric columns."""

    numeric_df = dataset.select_dtypes(include=["number"])
    print("\nDescriptive statistics (numeric columns):")
    print(numeric_df.describe().transpose())


def print_min_max_checks(dataset: pd.DataFrame, columns: Iterable[str]) -> None:
    """Print min/max values for important columns."""

    print("\nMin/Max checks:")
    for column in columns:
        if column in dataset.columns:
            print(f"- {column}: min={dataset[column].min()}, max={dataset[column].max()}")


def validate_dataset(dataset: pd.DataFrame) -> List[str]:
    """Validate core integrity constraints and return warning messages."""

    warnings: List[str] = []

    invalid_critical_vuln = dataset["critical_vulnerability_count"] > dataset["vulnerability_count"]
    if invalid_critical_vuln.any():
        warnings.append(
            "critical_vulnerability_count exceeds vulnerability_count "
            f"in {int(invalid_critical_vuln.sum())} rows."
        )

    for column in COUNT_COLUMNS:
        if column not in dataset.columns:
            warnings.append(f"Missing expected count column: {column}")
            continue
        negative_rows = dataset[column] < 0
        if negative_rows.any():
            warnings.append(
                f"Negative values found in {column} for {int(negative_rows.sum())} rows."
            )

    if "asset_type" not in dataset.columns:
        warnings.append("Missing expected column: asset_type")
    else:
        blank_asset_type = dataset["asset_type"].astype(str).str.strip() == ""
        if blank_asset_type.any():
            warnings.append(
                f"Blank asset_type found in {int(blank_asset_type.sum())} rows."
            )

    if "attack_path_count" in dataset.columns and "shortest_path_length" in dataset.columns:
        invalid_no_path_length = (dataset["attack_path_count"] == 0) & (dataset["shortest_path_length"] != 0)
        if invalid_no_path_length.any():
            warnings.append(
                "shortest_path_length must be 0 when attack_path_count is 0 "
                f"(violations: {int(invalid_no_path_length.sum())})."
            )

        invalid_positive_path_length = (dataset["attack_path_count"] > 0) & (dataset["shortest_path_length"] < 1)
        if invalid_positive_path_length.any():
            warnings.append(
                "shortest_path_length must be >= 1 when attack_path_count > 0 "
                f"(violations: {int(invalid_positive_path_length.sum())})."
            )
    else:
        warnings.append("Missing attack_path_count and/or shortest_path_length columns for path validation.")

    if "risk_level" not in dataset.columns:
        warnings.append("Missing expected column: risk_level")
    else:
        # risk_score removed to prevent ML data leakage; validate label values directly.
        invalid_levels = ~dataset["risk_level"].isin(VALID_RISK_LEVELS)
        if invalid_levels.any():
            warnings.append(
                f"Invalid risk_level values found in {int(invalid_levels.sum())} rows; "
                f"allowed values are {sorted(VALID_RISK_LEVELS)}."
            )

    return warnings


def print_validation_result(warnings: List[str]) -> None:
    """Print validation outcome with clear warnings when issues exist."""

    if not warnings:
        print("\nValidation checks: PASS (all checks succeeded)")
        return

    print("\nValidation checks: FAILED")
    for warning in warnings:
        print(f"ERROR: {warning}")


def main() -> None:
    """Run dataset inspection and sanity validations."""

    dataset = load_dataset()
    print_basic_summary(dataset)
    print_numeric_statistics(dataset)
    print_min_max_checks(dataset, IMPORTANT_COLUMNS)
    warnings = validate_dataset(dataset)
    print_validation_result(warnings)


if __name__ == "__main__":
    main()
