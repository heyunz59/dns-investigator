"""Per-origin authorization and DNS-pinned connections; never changes HTTP host/SNI."""
import asyncio
import ipaddress
import socket
import ssl
from contextlib import contextmanager
import certifi
import httpcore
import httpx


class HTTPRefused(Exception):
    def __init__(self,code):self.code=code;super().__init__(code)


class HTTPPolicy:
    def __init__(self,target_url,allowed_origins=(),allowed_networks=()):
        self.origins={self.origin(target_url),*(self.origin(x) for x in allowed_origins)}
        scheme,host,port=self.origin(target_url)
        if scheme=="http" and port==80:self.origins.add(("https",host,443))
        self.networks=tuple(ipaddress.ip_network(x,strict=True) for x in allowed_networks)

    @staticmethod
    def origin(value):
        try:
            url=httpx.URL(value)
            if url.scheme not in {"http","https"} or not url.host or url.userinfo or "%" in url.host:
                raise ValueError("invalid HTTP origin")
            port=url.port or (443 if url.scheme=="https" else 80)
            if not 1<=port<=65535:raise ValueError("invalid port")
            return url.scheme,url.host.lower().rstrip("."),port
        except (ValueError,httpx.InvalidURL) as exc:raise HTTPRefused("HTTP_URL_NOT_AUTHORIZED") from exc

    def authorize(self,url,redirect=False):
        try:origin=self.origin(url)
        except HTTPRefused as exc:
            if redirect:raise HTTPRefused("HTTP_REDIRECT_TARGET_NOT_AUTHORIZED") from exc
            raise
        if origin not in self.origins:
            raise HTTPRefused("HTTP_REDIRECT_TARGET_NOT_AUTHORIZED" if redirect else "HTTP_TARGET_NOT_AUTHORIZED")
        return origin

    def address(self,value):
        try:
            if "%" in value:raise ValueError("scoped IP")
            ip=ipaddress.ip_address(value)
            ip=getattr(ip,"ipv4_mapped",None) or ip
        except ValueError as exc:raise HTTPRefused("HTTP_TARGET_ADDRESS_NOT_AUTHORIZED") from exc
        if ip.is_multicast or ip.is_unspecified:raise HTTPRefused("HTTP_TARGET_ADDRESS_NOT_AUTHORIZED")
        public=ip.is_global and not ip.is_reserved and not ip.is_loopback and not ip.is_link_local
        if isinstance(ip,ipaddress.IPv6Address) and (ip.sixtofour or ip.teredo):public=False
        if not public and not any(ip in network for network in self.networks):
            raise HTTPRefused("HTTP_TARGET_ADDRESS_NOT_AUTHORIZED")
        return str(ip)


async def resolve(host,port):
    try:return [host] if ipaddress.ip_address(host) else []
    except ValueError:pass
    rows=await asyncio.get_running_loop().getaddrinfo(host,port,type=socket.SOCK_STREAM)
    return list(dict.fromkeys(row[4][0] for row in rows))


class AuthorizedBackend(httpcore.AsyncNetworkBackend):
    def __init__(self,policy,resolver=resolve,connector=None):
        self.policy,self.resolver=policy,resolver
        self.connector=connector or httpcore.AnyIOBackend()
        self.events=[]

    async def connect_tcp(self,host,port,timeout=None,local_address=None,socket_options=None):
        # Host was authorized by the transport. Validate the entire answer set before
        # choosing any address: mixed public/private answers fail closed.
        try:addresses=await self.resolver(host,port)
        except OSError as exc:raise httpcore.ConnectError("HTTP name resolution failed") from exc
        checked=list(dict.fromkeys(self.policy.address(ip) for ip in addresses))
        if not checked:raise httpcore.ConnectError("HTTP DNS returned no addresses")
        if len(checked)>16:raise HTTPRefused("HTTP_ADDRESS_BUDGET_EXHAUSTED")
        last=None
        for ip in checked:
            event=dict(host=host,port=port,validated_ip=ip,status="connecting")
            self.events.append(event)
            try:
                stream=await self.connector.connect_tcp(ip,port,timeout=timeout,local_address=local_address,socket_options=socket_options)
                event["status"]="connected"
                return stream
            except (httpcore.ConnectError,httpcore.ConnectTimeout) as exc:
                event["status"]=type(exc).__name__;last=exc
        raise last

    async def sleep(self,seconds):await asyncio.sleep(seconds)


@contextmanager
def map_errors():
    try:yield
    except (httpcore.TimeoutException,httpcore.NetworkError,httpcore.ProtocolError,httpcore.ProxyError,httpcore.UnsupportedProtocol) as exc:
        cls=getattr(httpx,type(exc).__name__,httpx.RequestError)
        raise cls("HTTP transport failed") from exc


class ResponseStream(httpx.AsyncByteStream):
    def __init__(self,stream):self.stream=stream
    async def __aiter__(self):
        with map_errors():
            async for chunk in self.stream:yield chunk
    async def aclose(self):await self.stream.aclose()


class PinnedTransport(httpx.AsyncBaseTransport):
    def __init__(self,policy,backend=None,ssl_context=None):
        self.policy=policy
        self.backend=backend or AuthorizedBackend(policy)
        context=ssl_context or ssl.create_default_context(cafile=certifi.where())
        if not context.check_hostname or context.verify_mode!=ssl.CERT_REQUIRED:
            raise ValueError("HTTPS requires hostname and certificate verification")
        # No pooled connection crosses request authorization or DNS decisions. All
        # redirects get a fresh, validated connection; max six HTTP requests per tool.
        self.pool=httpcore.AsyncConnectionPool(ssl_context=context,network_backend=self.backend,
            max_connections=1,max_keepalive_connections=0,http2=False,retries=0)

    async def handle_async_request(self,request):
        self.policy.authorize(str(request.url))
        if request.headers.get("host","").lower()!=request.url.netloc.decode("ascii").lower():
            raise HTTPRefused("HTTP_HOST_OVERRIDE_NOT_AUTHORIZED")
        if "sni_hostname" in request.extensions:raise HTTPRefused("HTTP_SNI_OVERRIDE_NOT_AUTHORIZED")
        req=httpcore.Request(method=request.method,url=httpcore.URL(scheme=request.url.raw_scheme,
            host=request.url.raw_host,port=request.url.port,target=request.url.raw_path),headers=request.headers.raw,
            content=request.stream,extensions=request.extensions)
        with map_errors():response=await self.pool.handle_async_request(req)
        return httpx.Response(response.status,headers=response.headers,stream=ResponseStream(response.stream),extensions=response.extensions)

    async def aclose(self):await self.pool.aclose()
