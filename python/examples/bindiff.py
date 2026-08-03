"""Compare two binaries with the Google BinDiff similarity provider (Ultimate only)."""

import argparse
import csv
import time
from pathlib import Path

from binaryninja import (
    BinaryView,
    LogLevel,
    SimilarityProviderType,
    SimilaritySession,
    SimilaritySessionNode,
    load,
)
from binaryninja.log import log_to_stdout
from binaryninja.similarity import SimilarityEntityInfo, SimilarityEntityType, SimilaritySessionCompletion


def wait_for_completion(completion: SimilaritySessionCompletion, timeout: float = 120) -> bool:
    """Wait up to ``timeout`` seconds for a similarity run to finish."""
    deadline = time.monotonic() + timeout
    while not completion.is_finished and time.monotonic() < deadline:
        time.sleep(0.1)
    return completion.is_finished


def diff(primary: BinaryView, secondary: BinaryView, output_csv: Path) -> int:
    """Compare two views and write their function matches to ``output_csv``."""
    provider_type = SimilarityProviderType["Google BinDiff"]
    provider_settings = provider_type.get_default_settings()
    provider = provider_type.create(provider_settings)

    session = SimilaritySession()
    session.add_provider(provider)
    primary_node = SimilaritySessionNode(primary)
    secondary_node = SimilaritySessionNode(secondary)
    session.graph.add_node(primary_node)
    session.graph.add_node(secondary_node)
    session.graph.add_edge(primary_node, secondary_node)

    completion = session.run()
    if not wait_for_completion(completion):
        completion.request_stop()
        wait_for_completion(completion, timeout=10)
        raise TimeoutError("BinDiff did not finish before the timeout")

    match_count = 0
    with output_csv.open("w", newline="") as output:
        writer = csv.writer(output)
        writer.writerow(["Address", "Function", "Matched Function", "Similarity", "Confidence"])
        for function in secondary.functions:
            entity = secondary_node.create_entity(
                SimilarityEntityInfo(SimilarityEntityType.SimilarityEntityFunction, function.start, function.name)
            )
            for result_id in secondary_node.get_results(entity):
                result = secondary_node.get_result(result_id)
                name = provider.get_name(secondary_node, entity, result_id)
                writer.writerow([hex(function.start), function.name, name, result.similarity, result.confidence])
                match_count += 1
    return match_count


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("primary", help="baseline binary")
    parser.add_argument("secondary", help="binary to compare")
    parser.add_argument("output", type=Path, help="output CSV path")
    args = parser.parse_args()

    log_to_stdout(LogLevel.WarningLog)
    with load(args.primary) as primary, load(args.secondary) as secondary:
        count = diff(primary, secondary, args.output)
    print(f"Wrote {count} matches to {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
