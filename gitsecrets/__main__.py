import sys

from .cli import main

# The guard matters: multiprocessing (spawn) re-imports this module in worker processes.
if __name__ == "__main__":
    sys.exit(main())
