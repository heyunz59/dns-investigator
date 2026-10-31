"""Safe structured exception-chain diagnostics; never persist exception text/URLs."""
import ssl


def describe(exc):
    seen=set();pending=[exc];chain=[];certificate=None;tls=False;timeout=False
    while pending and len(chain)<12:
        item=pending.pop(0)
        if id(item) in seen:continue
        seen.add(id(item));tls |= isinstance(item,ssl.SSLError)
        timeout |= isinstance(item,TimeoutError) or "Timeout" in type(item).__name__
        row={"type":type(item).__name__}
        for key in ("errno","winerror","verify_code"):
            value=getattr(item,key,None)
            if isinstance(value,int):row[key]=value
        if isinstance(item,ssl.SSLCertVerificationError):certificate=row
        chain.append(row)
        pending.extend(x for x in (item.__cause__,item.__context__) if isinstance(x,BaseException))
        pending.extend(x for x in item.args if isinstance(x,BaseException))
    code="CERTIFICATE_VERIFY_FAILED" if certificate else "TLS_ERROR" if tls else "TIMEOUT" if timeout else "CONNECTION_FAILED" if any("Connect" in r["type"] for r in chain) else "UNKNOWN_NETWORK_ERROR"
    return dict(code=code,chain=chain,certificate=certificate,
        message={"CERTIFICATE_VERIFY_FAILED":"明确的证书验证失败；具体原因以 verify_code 为准。","TLS_ERROR":"底层 TLS 错误，未确认是证书过期。","TIMEOUT":"本次连接或请求超时。","CONNECTION_FAILED":"连接失败，尚未定位 TLS 或证书原因。"}.get(code,"未识别的网络执行错误。"))
