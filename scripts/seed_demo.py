import sys

from fraudshield.cli import main


if __name__ == "__main__":
    sys.argv.insert(1, "seed-demo")
    main()
