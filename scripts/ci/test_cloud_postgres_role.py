"""B-632: the shared test Postgres role must never be a superuser.

Static half: scripts/cloud/postgres.sh never grants SUPERUSER and demotes an existing role.
Live half (when POSTGRES_TEST_URL is set): the advertised role really is not a superuser.
Run: python3 -m unittest scripts/ci/test_cloud_postgres_role.py
"""

import os
import re
import subprocess
import unittest
from pathlib import Path

SCRIPT = Path(__file__).resolve().parents[1] / "cloud" / "postgres.sh"


class CloudPostgresRole(unittest.TestCase):
    def test_script_never_grants_superuser(self):
        text = SCRIPT.read_text()
        code = "\n".join(
            line for line in text.splitlines() if not line.lstrip().startswith("#")
        )
        self.assertNotRegex(code, r"(?:CREATE|ALTER) ROLE[^;]*(?<!NO)SUPERUSER\b")
        self.assertRegex(
            code, r"CREATE ROLE tracelane LOGIN CREATEDB NOSUPERUSER NOCREATEROLE"
        )
        self.assertRegex(
            code, r"ALTER ROLE tracelane LOGIN CREATEDB NOSUPERUSER NOCREATEROLE"
        )

    def test_script_refuses_a_superuser_url(self):
        self.assertIn("refusing to advertise it", SCRIPT.read_text())

    def test_live_role_is_not_superuser(self):
        url = os.environ.get("POSTGRES_TEST_URL")
        if not url or not re.search(r"@(127\.0\.0\.1|localhost|\[::1\])", url):
            self.skipTest("no local POSTGRES_TEST_URL")
        out = subprocess.run(
            [
                "psql",
                url,
                "-tAc",
                "SELECT rolsuper FROM pg_roles WHERE rolname=current_user",
            ],
            capture_output=True,
            text=True,
            check=True,
        ).stdout.strip()
        self.assertEqual(out, "f")


if __name__ == "__main__":
    unittest.main()
