"""Recursive-assisted discovery, not independent root-to-zone iterative validation."""
import asyncio
from .dns_compare import compare


async def investigate_authority(backend, name, typ, timeout, parent):
    client=backend.dns
    discovery=[]
    answers=[]
    zone=None
    async with asyncio.timeout(backend.dns_tool_timeout):
        # Find the closest enclosing SOA owner; never assume last two labels form a zone.
        labels=name.split(".")
        for index in range(min(len(labels),8)):
            candidate=".".join(labels[index:])
            result=await client.query(candidate,"SOA",timeout=timeout,parent=parent)
            discovery.append(result)
            soa=[r for r in result.get("answer",[])+result.get("authority",[]) if r["type"]=="SOA"]
            if soa:
                owner=soa[0]["name"]
                if name==owner or name.endswith("."+owner):
                    zone=owner
                    break
            if result.get("error",{}):
                break
        if not zone:
            return dict(discovery=discovery,responses=[],zone=None,discovery_status="ZONE_UNKNOWN",
                        limitation="Discovery depends on recursive DNS; not iterative validation.")
        ns=await client.query(zone,"NS",timeout=timeout,parent=parent)
        discovery.append(ns)
        hosts=[r["value"].rstrip(".") for r in ns.get("records",[])][:backend.max_auth_servers]
        for host in hosts:
            addresses=await client.query(host,"A",timeout=timeout,parent=parent)
            discovery.append(addresses)
            if not addresses.get("records"):
                addresses=await client.query(host,"AAAA",timeout=timeout,parent=parent)
                discovery.append(addresses)
            ips=[r["value"] for r in addresses.get("records",[]) if client.permitted(r["value"],authoritative=True)]
            if not ips:
                continue
            ip=ips[0]  # one address per NS; bounded and no arbitrary user-supplied server
            response=await client.query(name,typ,ip,timeout,parent,role="authoritative")
            response["ns_name"]=host
            answers.append(response)
            if typ != "SOA":
                soa=await client.query(zone,"SOA",ip,timeout,parent,role="authoritative")
                soa["ns_name"]=host
                answers.append(soa)
    return dict(zone=zone,discovery=discovery,responses=answers,discovery_status="RECURSIVE_ASSISTED",
                differences=compare([r for r in answers if r.get("qtype")==typ]),
                limitation="Discovery depends on recursive DNS; AA is required for authoritative findings; no DNSSEC validation.")
