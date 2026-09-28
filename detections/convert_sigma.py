"""
Converte as regras Sigma de detections/sigma para consultas Elastic (ECS).

Uso:
    python detections/convert_sigma.py            # Lucene e EQL
    python detections/convert_sigma.py --target eql

Requer: pip install -r requirements-dev.txt
"""

from __future__ import annotations

import argparse

from pathlib import Path

from sigma.backends.elasticsearch import EqlBackend, LuceneBackend
from sigma.collection import SigmaCollection
from sigma.processing.pipeline import ProcessingItem, ProcessingPipeline
from sigma.processing.transformations import FieldMappingTransformation


SIGMA_DIRECTORY = Path(__file__).resolve().parent / "sigma"

# Campos Sigma de macOS → ECS (Elastic Defend).
ECS_MACOS = ProcessingPipeline(
    name="ecs_macos_elastic_defend",
    priority=20,
    items=[
        ProcessingItem(
            identifier="ecs_macos_fields",
            transformation=FieldMappingTransformation(
                {
                    "Image": "process.executable",
                    "CommandLine": "process.command_line",
                    "ParentImage": "process.parent.executable",
                    "TargetFilename": "file.path",
                }
            ),
        )
    ],
)

BACKENDS = {
    "lucene": LuceneBackend,
    "eql": EqlBackend,
}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--target",
        choices=sorted(BACKENDS),
        action="append",
    )
    targets = parser.parse_args().target or sorted(BACKENDS)

    for path in sorted(SIGMA_DIRECTORY.glob("*.yml")):
        collection = SigmaCollection.from_yaml(
            path.read_text(encoding="utf-8")
        )
        rule = collection.rules[0]

        print(f"### {rule.title} ({path.name})")

        for target in targets:
            query = BACKENDS[target](ECS_MACOS).convert(collection)[0]
            print(f"[{target}] {query}")

        print()


if __name__ == "__main__":
    main()
