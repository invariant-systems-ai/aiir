"""Allow running aiir as `python -m aiir`."""

import sys

from aiir.cli import main

try:
    raise SystemExit(main())
except KeyboardInterrupt:
    # Clean exit on Ctrl-C — no traceback.
    print("\nInterrupted.", file=sys.stderr)
    raise SystemExit(130)
except MemoryError:
    print("Error: out of memory", file=sys.stderr)
    raise SystemExit(1)
