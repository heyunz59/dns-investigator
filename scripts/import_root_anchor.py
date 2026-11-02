"""Maintainer-only authenticated snapshot import. Never called by an Agent/tool.

Verify IANA XML's detached CMS and pinned ICANN CA chain before any replacement.
The destination is a software asset directory, not an RFC5011 trust store.
"""
import argparse
import hashlib
import json
import shutil
import subprocess
import tempfile
from datetime import datetime, timezone
from pathlib import Path

from dns_investigator.trust import ICANN_CA_SHA256, anchors

NAMES = ("root-anchors.xml", "root-anchors.p7s", "icannbundle.pem")


def import_snapshot(source, destination, *, replace=False, powershell="pwsh"):
    source, destination = Path(source).resolve(), Path(destination).resolve()
    if source == destination:
        raise ValueError("Import source must be separate from the active snapshot")
    if destination.exists() and not replace:
        raise FileExistsError("Use --replace explicitly for a maintained software snapshot")
    # Validate bounded inputs before invoking the authenticated verifier.
    for filename in NAMES:
        p = source / filename
        if not p.is_file() or not 0 < p.stat().st_size <= 65536:
            raise ValueError("Missing or oversized IANA anchor material")
    destination.parent.mkdir(parents=True, exist_ok=True)
    verifier = Path(__file__).with_name("verify_anchor_cms.ps1")
    with tempfile.TemporaryDirectory(prefix="anchor-import-", dir=destination.parent) as temporary:
        stage = Path(temporary) / "assets"
        if destination.exists():
            shutil.copytree(destination, stage)
        else:
            stage.mkdir()
        for filename in NAMES:
            shutil.copyfile(source / filename, stage / filename)
        # The pin is compiled in trusted software. It is not supplied by the input
        # directory, the downloaded bundle, a DNS response, or model arguments.
        subprocess.run([powershell, "-NoProfile", "-File", str(verifier),
                        "-Directory", str(stage), "-ExpectedBundleSha256", ICANN_CA_SHA256,
                        "-Receipt", str(stage / "anchor-authentication.json")],
                       check=True, capture_output=True, timeout=30)
        anchors(directory=stage)  # Also verify XML structure, dates and active DS.
        sources_path = stage / "sources.json"
        sources = json.loads(sources_path.read_text()) if sources_path.exists() else {}
        sources["authenticated_anchor_import"] = dict(
            imported_at=datetime.now(timezone.utc).isoformat(),
            source="https://data.iana.org/root-anchors/", authentication="detached CMS + pinned ICANN CA",
            hashes={n: hashlib.sha256((stage / n).read_bytes()).hexdigest() for n in NAMES})
        sources_path.write_text(json.dumps(sources, indent=2)+"\n", encoding="utf-8")
        # Only authenticated staging is installed. Keep old assets until rename
        # succeeds; failure rolls back. Readers fail closed during the short swap.
        backup = Path(temporary) / "previous"
        if destination.exists():
            destination.rename(backup)
        try:
            stage.rename(destination)
        except BaseException:
            if backup.exists():
                backup.rename(destination)
            raise
    return dict(authentication="CMS_SIGNATURE_AND_PINNED_ICANN_CA_CHAIN", replaced=replace)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("source", type=Path)
    parser.add_argument("destination", type=Path)
    parser.add_argument("--replace", action="store_true")
    parser.add_argument("--powershell", default="pwsh")
    args = parser.parse_args()
    print(json.dumps(import_snapshot(args.source, args.destination, replace=args.replace, powershell=args.powershell)))
