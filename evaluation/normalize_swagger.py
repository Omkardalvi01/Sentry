#!/usr/bin/env python3
"""Rename non-OpenAPI-3 schema identifiers in generated Swagger 2 documents.

Springfox emits generic names such as Map«string,Link». The Swagger 2 source
is retained; this copy only changes definition keys and matching local refs.
"""

import argparse
import hashlib
import json
import re
from pathlib import Path


VALID = re.compile(r"^[A-Za-z0-9._-]+$")


def normalize(document):
    definitions = document.get("definitions", {})
    used = set(definitions)
    renames = {}
    for name in definitions:
        if VALID.fullmatch(name):
            continue
        base = re.sub(r"[^A-Za-z0-9._-]", "_", name)
        replacement = base
        if replacement in used:
            replacement = base + "_" + hashlib.sha256(name.encode()).hexdigest()[:8]
        while replacement in used:
            replacement += "_"
        used.add(replacement)
        renames[name] = replacement
    if not renames:
        return document, {}
    document["definitions"] = {renames.get(name, name): value for name, value in definitions.items()}

    def walk(value):
        if isinstance(value, dict):
            for key, item in value.items():
                if key == "$ref" and isinstance(item, str) and item.startswith("#/definitions/"):
                    encoded = item.removeprefix("#/definitions/")
                    name = encoded.replace("~1", "/").replace("~0", "~")
                    if name in renames:
                        value[key] = "#/definitions/" + renames[name]
                else:
                    walk(item)
        elif isinstance(value, list):
            for item in value:
                walk(item)

    walk(document)
    return document, renames


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("input", type=Path)
    parser.add_argument("output", type=Path)
    args = parser.parse_args()
    document, renames = normalize(json.loads(args.input.read_text()))
    args.output.write_text(json.dumps(document, indent=2, sort_keys=True) + "\n")
    print(json.dumps({"renamed_definitions": renames, "output": str(args.output)}, indent=2))


if __name__ == "__main__":
    main()
