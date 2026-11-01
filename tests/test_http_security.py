import ssl
import pytest
import httpcore
from dns_investigator.http_safety import HTTPPolicy,AuthorizedBackend,PinnedTransport
from dns_investigator.tools import ToolBackend
from dns_investigator.target import parse_target


class Stream(httpcore.AsyncNetworkStream):
    def __init__(self,response,connector):self.response=response;self.connector=connector
    async def read(self,max_bytes,timeout=None):
        result,self.response=self.response,b"";return result
    async def write(self,buffer,timeout=None):self.connector.writes.append(buffer)
    async def aclose(self):pass
    async def start_tls(self,ssl_context,server_hostname=None,timeout=None):
        self.connector.tls.append((server_hostname,ssl_context.check_hostname,ssl_context.verify_mode));return self
    def get_extra_info(self,key):return ("93.184.216.34",443) if key=="server_addr" else None


class Connector:
    def __init__(self,responses):self.responses=list(responses);self.calls=[];self.tls=[];self.writes=[]
    async def connect_tcp(self,host,port,**kw):
        self.calls.append((host,port));return Stream(self.responses.pop(0),self)


def response(location=None):
    return (b"HTTP/1.1 302 Found\r\nLocation: "+location.encode()+b"\r\nContent-Length: 0\r\n\r\n") if location else b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK"


def backend(responses,answers=None,origins=()):
    b=ToolBackend(parse_target("https://allowed.example/"))
    b.http_policy=HTTPPolicy(b.target.url,origins)
    connector=Connector(responses);resolutions=[]
    async def resolver(host,port):
        resolutions.append(host)
        return answers[len(resolutions)-1] if answers else ["93.184.216.34"]
    def transport(policy):return PinnedTransport(policy,AuthorizedBackend(policy,resolver,connector))
    b.http_transport_factory=transport
    return b,connector,resolutions


@pytest.mark.parametrize("location",["http://127.0.0.1/","http://169.254.169.254/","http://10.0.0.1/","http://[::1]/","https://other.example/","https://allowed.example:444/","https://user:pass@allowed.example/"])
async def test_unauthorized_redirect_never_opens_second_connection(location):
    b,c,dns=backend([response(location)])
    r=await b.check_http(b.target.url)
    assert r["error"] in {"HTTP_REDIRECT_TARGET_NOT_AUTHORIZED","HTTP_URL_NOT_AUTHORIZED","UNSUPPORTED_REDIRECT"}
    assert len(c.calls)==len(dns)==1 and r["status_code"]==302
    assert r["redirects"] or r["error"]=="UNSUPPORTED_REDIRECT"


@pytest.mark.parametrize("addresses",[["127.0.0.1"],["::1"],["169.254.169.254"],["10.0.0.1"],["::ffff:127.0.0.1"],["93.184.216.34","10.0.0.1"],["224.0.0.1"]])
async def test_disallowed_dns_answers_fail_closed_without_evidence(addresses):
    b,c,dns=backend([],answers=[addresses])
    r=await b.call("check_http",url=b.target.url)
    assert r["error"]["code"]=="HTTP_TARGET_ADDRESS_NOT_AUTHORIZED"
    assert not c.calls and not b.calls and len(b.attempts)==1


async def test_rebinding_cannot_change_numeric_connection_target():
    b,c,dns=backend([response()],answers=[["93.184.216.34"],["127.0.0.1"]])
    r=await b.check_http(b.target.url)
    assert r["status_code"]==200 and dns==["allowed.example"]
    assert c.calls==[("93.184.216.34",443)]


async def test_same_origin_redirect_reresolves_and_blocks_rebinding():
    b,c,dns=backend([response("/next")],answers=[["93.184.216.34"],["127.0.0.1"]])
    r=await b.check_http(b.target.url)
    assert r["error"]=="HTTP_TARGET_ADDRESS_NOT_AUTHORIZED" and len(c.calls)==1 and len(dns)==2


async def test_authorized_https_redirect_keeps_host_sni_and_validation():
    b,c,_=backend([response("/next"),response()])
    r=await b.check_http(b.target.url)
    assert r["error"] is None and r["status_code"]==200 and r["final_url"].endswith("/next")
    assert c.tls==[("allowed.example",True,ssl.CERT_REQUIRED)]*2
    headers=[write for write in c.writes if write.startswith(b"GET ")]
    assert len(headers)==2 and all(b"Host: allowed.example\r\n" in write for write in headers)


async def test_explicit_cross_origin_authorization_and_redirect_budget():
    b,c,_=backend([response("https://cdn.example/end"),response()],origins=("https://cdn.example",))
    assert (await b.check_http(b.target.url))["error"] is None
    assert c.tls[-1][0]=="cdn.example"
    b,c,_=backend([response("/again")]*6)
    assert (await b.check_http(b.target.url))["error"]=="TOO_MANY_REDIRECTS"
    assert len(c.calls)==6


def test_cannot_disable_certificate_validation():
    context=ssl._create_unverified_context()
    with pytest.raises(ValueError):PinnedTransport(HTTPPolicy("https://allowed.example"),ssl_context=context)


@pytest.mark.parametrize("hostname",["allowed.example","wrong.example"])
async def test_real_controlled_tls_validates_certificate_and_preserves_sni(tmp_path,hostname):
    import asyncio
    from datetime import datetime,timedelta,timezone
    from cryptography import x509
    from cryptography.x509.oid import NameOID
    from cryptography.hazmat.primitives import hashes,serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    key,cert=tmp_path/"key.pem",tmp_path/"cert.pem"
    private=rsa.generate_private_key(public_exponent=65537,key_size=2048)
    subject=x509.Name([x509.NameAttribute(NameOID.COMMON_NAME,"allowed.example")])
    certificate=(x509.CertificateBuilder().subject_name(subject).issuer_name(subject).public_key(private.public_key())
        .serial_number(x509.random_serial_number()).not_valid_before(datetime.now(timezone.utc)-timedelta(minutes=1))
        .not_valid_after(datetime.now(timezone.utc)+timedelta(days=1))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName("allowed.example")]),critical=False).sign(private,hashes.SHA256()))
    key.write_bytes(private.private_bytes(serialization.Encoding.PEM,serialization.PrivateFormat.PKCS8,serialization.NoEncryption()))
    cert.write_bytes(certificate.public_bytes(serialization.Encoding.PEM))
    server_context=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER);server_context.load_cert_chain(cert,key)
    names=[];headers=[]
    server_context.set_servername_callback(lambda sock,name,ctx:names.append(name))
    async def handler(reader,writer):
        try:
            data=await reader.readuntil(b"\r\n\r\n");headers.append(data)
            writer.write(response("/final") if data.startswith(b"GET /start ") else response());await writer.drain()
        finally:writer.close()
    server=await asyncio.start_server(handler,"127.0.0.1",0,ssl=server_context)
    port=server.sockets[0].getsockname()[1]
    class LocalConnector:
        async def connect_tcp(self,host,port,**kw):
            assert host=="93.184.216.34"  # authorization is enforced before test-only routing
            return await httpcore.AnyIOBackend().connect_tcp("127.0.0.1",port,**kw)
    async def resolver(host,port):return ["93.184.216.34"]
    client_context=ssl.create_default_context(cafile=cert)
    b=ToolBackend(parse_target(f"https://{hostname}:{port}/start"))
    b.http_transport_factory=lambda p:PinnedTransport(p,AuthorizedBackend(p,resolver,LocalConnector()),client_context)
    try:
        r=await b.check_http(b.target.url)
        assert names and all(name==hostname for name in names)
        if hostname=="allowed.example":
            assert r["status_code"]==200 and r["error"] is None and len(headers)==2
            assert all(f"Host: {hostname}:{port}\r\n".encode() in h for h in headers)
        else:
            assert r["error_detail"]["code"]=="CERTIFICATE_VERIFY_FAILED" and not headers
    finally:server.close();await server.wait_closed()
