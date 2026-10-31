"""Pre-push audit of every tracked version (never prints matched secret values)."""
import re
import subprocess
import sys
from pathlib import Path


def check():
    problems = []
    versions = subprocess.check_output(["git", "rev-list", "--all"], text=True).splitlines()
    for ref in [None] + versions:
        names = subprocess.check_output(["git", "ls-files"] if ref is None else ["git", "ls-tree", "-r", "--name-only", ref], text=True).splitlines()
        for name in names:
            p = Path(name)
            if p.name.startswith(".env") and p.name != ".env.example" or any(s in name for s in (".venv/", "results/runs/", "results/evaluation-raw/")):
                problems.append((name, "private file tracked"))
            data = p.read_bytes() if ref is None else subprocess.check_output(["git", "show", f"{ref}:{name}"])
            if p.suffix in {".png", ".jpg"}:
                continue
            text = data.decode("utf-8", errors="replace")
            patterns = [r"sk-[A-Za-z0-9_-]{16,}", r"gh[pousr]_[A-Za-z0-9_]{20,}",
                        r"github_pat_[A-Za-z0-9_]{20,}", r"-----BEGIN (?:RSA |OPENSSH )?PRIVATE KEY-----",
                        r"(?i)[A-Z]:[\\/]Users[\\/]", r"(?im)^DEEPSEEK_API_KEY[ \t]*=[ \t]*\S+"]
            for pattern in patterns:
                if re.search(pattern, text):
                    problems.append((name, "secret or local personal path pattern"))
    for name, reason in sorted(set(problems)):
        print(f"FAIL: {name}: {reason}")
    print("Public audit:", "FAIL" if problems else "PASS", "(pattern scan; manual review still required)")
    return bool(problems)


if __name__ == "__main__":
    sys.exit(check())
