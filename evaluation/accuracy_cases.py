"""Fixed observations only. Expectations live separately and never enter Agent context."""
import copy


def evidence(index, kind="NOERROR", resolver="1.1.1.1", role="recursive", **updates):
    data=dict(qname="probe.example",qtype="A",resolver=resolver,resolver_role=role,
        rcode=kind if kind!="NODATA" else "NOERROR",result_kind=kind,
        records=[dict(value="192.0.2.10",ttl=60)] if kind=="NOERROR" else [],
        flags=dict(AA=role=="authoritative",TC=False),execution_status="ok",duration_ms=10)
    data.update(updates)
    return dict(id=f"E{index}",tool_name="query_dns",tool_call_id=f"A{index}",query_attempt_id=f"Q{index}",
        input=dict(domain=data["qname"],record_type=data["qtype"]),data=data,
        started_at="2026-11-01T00:00:00+00:00",execution_status="ok",source_mode="synthetic")


def cases():
    ok=evidence(1)
    second=evidence(2,resolver="8.8.8.8")
    return copy.deepcopy(dict(
        timeout=[evidence(1,"TIMEOUT"),second],
        nxdomain=[evidence(1,"NXDOMAIN",negative_name="probe.example"),second],
        servfail=[evidence(1,"SERVFAIL"),second],
        cdn=[ok,evidence(2,resolver="8.8.8.8",records=[dict(value="192.0.2.11",ttl=60)])],
        ttl=[ok,evidence(2,resolver="8.8.8.8",records=[dict(value="192.0.2.10",ttl=58)])],
        referral=[evidence(1,"NOERROR",result_kind="REFERRAL",records=[],cname_chain=[dict(name="probe.example",target="target.other")]),second],
        alias=[evidence(1,"NOERROR",result_kind="ALIAS_INCOMPLETE",records=[],cname_chain=[dict(name="probe.example",target="target.other")])],
        non_aa=[evidence(1,"NXDOMAIN"),evidence(2,role="authoritative",flags=dict(AA=False,TC=False))],
        serial=[evidence(1,role="authoritative",qtype="SOA",soa_serials=[1],records=[dict(value="ns.example host.example 1 60 60 60 60",ttl=60)]),
                evidence(2,resolver="8.8.8.8",role="authoritative",qtype="SOA",soa_serials=[2],records=[dict(value="ns.example host.example 2 60 60 60 60",ttl=60)])],
        partial=[evidence(1,"TIMEOUT"),evidence(2,"NXDOMAIN",resolver="8.8.8.8"),evidence(3,resolver="9.9.9.9")],
        no_measurement=[],normal=[ok,second],
        recursive_auth=[evidence(1,"NXDOMAIN"),evidence(2,role="authoritative")],
    ))
