"""Bounded EDNS observations. Server text is data, never local validation."""
import dns.edns
import dns.flags
import dns.rcode
import re
from .privacy import redact


def metadata(message):
    errors=[];other=[]
    for option in message.options:
        if int(option.otype)!=15:
            other.append(dict(type=int(option.otype),length=len(option.to_wire())));continue
        raw=option.to_wire()
        if len(raw)<2:
            errors.append(dict(malformed=True,provenance="server_reported",text="[malformed EDE]"));continue
        code=int.from_bytes(raw[:2],"big")
        name=dns.edns.EDECode(code).name if code in {int(x) for x in dns.edns.EDECode} else "UNKNOWN"
        # Never keep an alternate unredacted/base64 copy of server-controlled text.
        value=redact(raw[2:].rstrip(b"\0").decode("utf-8",errors="replace"))
        value=re.sub(r"(?i)(?:token|password|authorization|api[_-]?key)\s*[:=]\s*\S+","[redacted]",value)
        value=re.sub(r"(?i)[a-z]:[\\/]users[\\/][^\s]+","[local-path]",value)
        text="".join(c if c.isprintable() else f"\\u{ord(c):04x}" for c in value)
        errors.append(dict(code=code,name=name,text=text[:256],text_truncated=len(text)>256,
            text_untrusted=True,provenance="server_reported",source_label="REPORTED_BY_SERVER",
            mapping_version="dnspython-2.9.1-EDECode"))
    return dict(header_rcode=dns.rcode.to_text(message.flags&15),
        edns=dict(present=message.edns>=0,version=message.edns,udp_payload=message.payload,
            do=bool(message.ednsflags&dns.flags.DO),other_options=other[:32]),ede=errors[:16],
        ede_omitted_count=max(0,len(errors)-16))
