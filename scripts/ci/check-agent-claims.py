#!/usr/bin/env python3
"""Cooperative path claims, checked at commit time across linked worktrees.

Measured gap: author and roadmap hooks do not check path ownership. A claim
protects commits, not arbitrary writes or a hostile agent disabling hooks.
"""

import argparse
import fcntl
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path, PurePosixPath


def identity(pid):
    try:
        # The process start tick distinguishes PID reuse. Linux operator host.
        fields = Path(f"/proc/{pid}/stat").read_text().rsplit(")", 1)[1].split()
        return None if fields[0] in ("Z", "X") else fields[19]
    except (OSError, IndexError):
        return None


def conflicts(claims, paths, owner, alive=identity):
    paths = {str(PurePosixPath(path)) for path in paths}
    return [
        str(PurePosixPath(path))
        for path, claim in claims.items()
        if str(PurePosixPath(path)) in paths
        and claim["owner"] != owner
        and alive(claim["pid"]) == claim["start"]
    ]


def selftest():
    claims = {"src/a.py": {"owner": "other", "pid": 42, "start": "start"}}
    alive = lambda pid: "start" if pid == 42 else None
    assert conflicts(claims, ["src/a.py"], "mine", alive), (
        "active foreign claim MUST BLOCK"
    )
    assert not conflicts(claims, ["src/a.py"], "other", alive)
    assert not conflicts(claims, ["src/b.py"], "mine", alive)
    assert not conflicts(claims, ["src/a.py"], "mine", lambda pid: None)
    assert not conflicts(claims, ["src/a.py"], "mine", lambda pid: "new-pid")
    child = os.fork()
    if child == 0:
        os._exit(0)
    try:
        os.waitid(os.P_PID, child, os.WEXITED | os.WNOWAIT)
        assert identity(child) is None, "a dead, unreaped agent MUST release its claim"
    finally:
        os.waitpid(child, 0)
    with tempfile.TemporaryDirectory() as tmp:
        env = {k: v for k, v in os.environ.items() if not k.startswith("GIT_")}
        subprocess.run(["git", "init", "-q", tmp], env=env, check=True)
        source = Path(tmp) / "source.py"
        source.write_text("changed")
        subprocess.run(["git", "-C", tmp, "add", "source.py"], env=env, check=True)

        def run(*args):
            return subprocess.run(
                [sys.executable, str(Path(__file__).resolve()), *args],
                cwd=tmp,
                env=env,
                capture_output=True,
                text=True,
                check=False,
            )

        assert (
            run(
                "--claim", "source.py", "--owner", "other", "--pid", str(os.getpid())
            ).returncode
            == 0
        )
        assert run("--owner", "mine").returncode == 1
        assert run("--owner", "other").returncode == 0
        assert (
            run(
                "--claim", "../escape", "--owner", "mine", "--pid", str(os.getpid())
            ).returncode
            == 1
        )
        assert run("--release", "--owner", "other").returncode == 0
        assert run("--owner", "mine").returncode == 0
        assert (
            run(
                "--claim", "./source.py", "--owner", "other", "--pid", str(os.getpid())
            ).returncode
            == 0
        )
        assert run("--owner", "mine").returncode == 1, (
            "equivalent path spelling MUST NOT bypass the live claim"
        )
        # Already-written claims also need canonical comparison, without a migration.
        store = Path(tmp) / ".git/agent-claims.json"
        stored = json.loads(store.read_text())
        store.write_text(json.dumps({"./source.py": next(iter(stored.values()))}))
        assert run("--owner", "mine").returncode == 1
        (Path(tmp) / ".git/agent-claims.json").write_text("invalid json")
        assert run("--owner", "mine").returncode == 1
    print(
        "claims selftest: 6 blocking fixtures refused; 10 clean/stale/ownership cases accepted"
    )
    return 0


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--selftest", action="store_true")
    parser.add_argument("--claim", nargs="+")
    parser.add_argument("--release", action="store_true")
    parser.add_argument("--owner", default=os.environ.get("TRACELANE_AGENT_ID", ""))
    parser.add_argument("--pid", type=int)
    args = parser.parse_args()
    if args.selftest:
        return selftest()
    try:
        common = Path(
            subprocess.check_output(
                ["git", "rev-parse", "--git-common-dir"], text=True
            ).strip()
        ).resolve()
        storage = common / "agent-claims.json"
        with (common / "agent-claims.lock").open("a") as lock:
            fcntl.flock(lock, fcntl.LOCK_EX)
            claims = json.loads(storage.read_text()) if storage.exists() else {}
            if not isinstance(claims, dict):
                raise TypeError("malformed claim store")
            for path, claim in claims.items():
                if (
                    not isinstance(claim, dict)
                    or not isinstance(claim.get("pid"), int)
                    or not isinstance(claim.get("start"), str)
                    or not claim.get("owner")
                ):
                    raise ValueError("malformed claim record: " + path)
            if args.claim or args.release:
                if not args.owner:
                    raise ValueError("claim/release requires --owner")
                if args.release:
                    claims = {
                        p: c for p, c in claims.items() if c["owner"] != args.owner
                    }
                else:
                    start = identity(args.pid)
                    if not start:
                        raise ValueError("--pid must identify the live agent process")
                    for p in args.claim:
                        if (
                            PurePosixPath(p).is_absolute()
                            or ".." in PurePosixPath(p).parts
                        ):
                            raise ValueError("claims must be repository-relative paths")
                    bad = conflicts(claims, args.claim, args.owner)
                    if bad:
                        raise ValueError("active foreign claims: " + ", ".join(bad))
                    claims.update(
                        {
                            str(PurePosixPath(p)): {
                                "owner": args.owner,
                                "pid": args.pid,
                                "start": start,
                            }
                            for p in args.claim
                        }
                    )
                with tempfile.NamedTemporaryFile(
                    mode="w", dir=common, delete=False
                ) as out:
                    json.dump(claims, out)
                    tmp = out.name
                os.replace(tmp, storage)
            else:
                paths = subprocess.check_output(
                    ["git", "diff", "--cached", "--name-only", "--no-renames"],
                    text=True,
                ).splitlines()
                bad = conflicts(claims, paths, args.owner)
                if bad:
                    raise ValueError("active foreign claims: " + ", ".join(bad))
        return 0
    except (
        OSError,
        ValueError,
        KeyError,
        TypeError,
        subprocess.SubprocessError,
    ) as exc:
        print("BLOCKED: agent claims: " + str(exc), file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
