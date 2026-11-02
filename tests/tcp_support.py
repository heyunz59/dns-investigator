"""Explicit test-only network permission and injected current DNS evidence."""
import dns.message,dns.rrset
from dns_investigator.dns_wire import parse_response
from dns_investigator.network_policy import networks

def authorize(b,ip,port=443):
    b.tcp_networks=networks((ip+'/128' if ':' in ip else ip+'/32',))
    from dns_investigator.target import parse_target
    b.target=parse_target('https://example.com:'+str(port))
    typ='AAAA' if ':' in ip else 'A'
    m=dns.message.make_response(dns.message.make_query(b.target.domain,typ))
    m.answer.append(dns.rrset.from_text(b.target.domain+'.',60,'IN',typ,ip))
    b.add_dns_evidence(parse_response(m,b.target.domain,typ,'1.1.1.1'),'TEST_DNS')
    return b
