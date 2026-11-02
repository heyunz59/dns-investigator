"""Software-distributed, CMS-authenticated anchors; never accept keys from the Agent."""
from datetime import datetime,timezone
import hashlib,json
from importlib.resources import files
import xml.etree.ElementTree as ET

ICANN_CA_SHA256="18ce7215812d1a2cad8d9d4d3d7c26f7235a9b5ec6f0c1e214e15230fd4f9e24"


def anchors(now=None,*,directory=None):
    now=datetime.now(timezone.utc) if now is None else datetime.fromtimestamp(now,timezone.utc)
    # Alternate directories are an internal maintainer/test interface, never a
    # model/tool parameter. Runtime uses only the distributed software snapshot.
    asset=directory if directory is not None else files("dns_investigator").joinpath("assets")
    raw=asset.joinpath("root-anchors.xml").read_bytes()
    receipt=json.loads(asset.joinpath("anchor-authentication.json").read_text(encoding="utf-8-sig"))
    bundle=asset.joinpath("icannbundle.pem").read_bytes()
    if (receipt.get("authentication")!="CMS_SIGNATURE_AND_PINNED_ICANN_CA_CHAIN" or
        hashlib.sha256(raw).hexdigest()!=receipt.get("xml_sha256") or
        hashlib.sha256(bundle).hexdigest()!=ICANN_CA_SHA256 or receipt.get("bundle_sha256")!=ICANN_CA_SHA256):
        raise ValueError("TRUST_ANCHOR_AUTHENTICATION_FAILED")
    verified=datetime.fromisoformat(receipt["verified_at"])
    if not 0<=(now-verified).total_seconds()<=180*86400:raise ValueError("TRUST_ANCHOR_UPDATE_REQUIRED")
    if len(raw)>65536:raise ValueError("TRUST_ANCHOR_RESOURCE_LIMIT")
    root=ET.fromstring(raw)
    if root.findtext("Zone")!=".":raise ValueError("ROOT_ANCHOR_ZONE_MISMATCH")
    records=[]
    for key in root.findall("KeyDigest"):
        if datetime.fromisoformat(key.attrib["validFrom"])>now:continue
        if key.get("validUntil") and datetime.fromisoformat(key.get("validUntil"))<now:continue
        records.append(" ".join(key.findtext(field).strip() for field in ("KeyTag","Algorithm","DigestType","Digest")))
    if not records:raise ValueError("NO_VALID_TRUST_ANCHOR")
    return dict(zone=".",ds=records,source="IANA CMS-authenticated software snapshot",
        version=receipt["xml_sha256"],authentication=receipt["authentication"],verified_at=receipt["verified_at"],
        maintenance="explicit authenticated import/software update; max snapshot age 180d; no RFC5011 daemon",revocation=receipt["revocation"])
