"""Private subprocess launcher: impose resource ceilings before invoking Git."""

import os
import resource
import sys


def main() -> None:
    """Run the fixed Git binary with bounded process resources."""
    resource.setrlimit(resource.RLIMIT_CPU, (30, 30))
    resource.setrlimit(resource.RLIMIT_FSIZE, (128 * 1024 * 1024, 128 * 1024 * 1024))
    resource.setrlimit(resource.RLIMIT_NOFILE, (128, 128))
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    if sys.platform == "linux":
        resource.setrlimit(resource.RLIMIT_AS, (768 * 1024 * 1024, 768 * 1024 * 1024))
    os.execv("/usr/bin/git", ["/usr/bin/git", *sys.argv[1:]])


if __name__ == "__main__":
    main()
