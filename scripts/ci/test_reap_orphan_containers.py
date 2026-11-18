"""reap-orphan-containers.sh removes only <prefix><pid> containers whose pid is gone."""

import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

SCRIPT = Path(__file__).with_name("reap-orphan-containers.sh")


class Reap(unittest.TestCase):
    def run_with(self, names, prefixes):
        with tempfile.TemporaryDirectory() as d:
            log = Path(d, "rm.log")
            fake = Path(d, "docker")
            listing = "\n".join(names)
            fake.write_text(
                "#!/usr/bin/env bash\n"
                f'if [ "$1" = ps ]; then printf "%s\\n" "{listing}"; exit 0; fi\n'
                f'if [ "$1" = rm ]; then shift; echo "$@" >> "{log}"; exit 0; fi\n'
                "exit 1\n"
            )
            fake.chmod(0o755)
            env = {**os.environ, "PATH": f"{d}:{os.environ['PATH']}"}
            subprocess.run(["bash", str(SCRIPT), *prefixes], check=True, env=env)
            return log.read_text().split() if log.exists() else []

    def test_dead_pid_reaped_live_kept(self):
        live = os.getpid()
        dead = 2**22 + 12345  # above the default pid_max, so never a live process
        removed = self.run_with(
            [
                f"tlane-ledger-pg-{live}",
                f"tlane-ledger-pg-{dead}",
                f"tlane-ledger-ch-{dead}",
            ],
            ["tlane-ledger-pg-", "tlane-ledger-ch-"],
        )
        self.assertIn(f"tlane-ledger-pg-{dead}", removed)
        self.assertIn(f"tlane-ledger-ch-{dead}", removed)
        self.assertNotIn(f"tlane-ledger-pg-{live}", removed)

    def test_other_prefixes_and_non_numeric_suffixes_untouched(self):
        dead = 2**22 + 12345
        removed = self.run_with(
            [f"tlane-nats-auth-{dead}", "tlane-ledger-pg-abc", f"other-{dead}"],
            ["tlane-ledger-pg-"],
        )
        self.assertEqual(removed, [])

    def test_no_docker_is_not_an_error(self):
        with tempfile.TemporaryDirectory() as d:
            env = {**os.environ, "PATH": d}
            r = subprocess.run(
                ["/bin/bash", str(SCRIPT), "tlane-x-"], env=env, check=False
            )
            self.assertEqual(r.returncode, 0)


if __name__ == "__main__":
    sys.exit(unittest.main())
