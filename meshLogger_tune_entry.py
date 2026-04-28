#!/usr/bin/env python3

import sys

import meshLogger


def main() -> int:
    if "--tune" not in sys.argv[1:]:
        sys.argv.insert(1, "--tune")
    return meshLogger.main()


if __name__ == "__main__":
    raise SystemExit(main())
