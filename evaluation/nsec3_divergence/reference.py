"""Independent Unbound 1.26.2 reference, TEST ONLY, never a runtime validator."""
import asyncio,ctypes,json,os,multiprocessing,time,tempfile
from contextlib import asynccontextmanager
from datetime import datetime,timezone
from pathlib import Path


class Result(ctypes.Structure):
    _fields_=[("qname",ctypes.c_char_p),("qtype",ctypes.c_int),("qclass",ctypes.c_int),
        ("data",ctypes.POINTER(ctypes.c_char_p)),("lengths",ctypes.POINTER(ctypes.c_int)),("canonname",ctypes.c_char_p),
        ("rcode",ctypes.c_int),("answer_packet",ctypes.c_void_p),("answer_len",ctypes.c_int),
        ("havedata",ctypes.c_int),("nxdomain",ctypes.c_int),("secure",ctypes.c_int),("bogus",ctypes.c_int),
        ("why_bogus",ctypes.c_char_p),("was_ratelimited",ctypes.c_int),("ttl",ctypes.c_int)]


@asynccontextmanager
async def reference_ports(lab):
    from evaluation.protocol_lab import UDP
    listeners=[]
    try:
        for i in range(3):
            t,_=await asyncio.get_running_loop().create_datagram_endpoint(lambda index=i:UDP(lab,index),local_addr=(f"127.0.0.{i+10}",53))
            listeners.append(t)
        yield
    finally:
        for t in listeners:t.close()


def resolve_worker(directory,config,pipe):
    directory=Path(directory)
    handles=[]
    if os.name=="nt":handles.append(os.add_dll_directory(str(directory/"libunbound")))
    lib=ctypes.CDLL(str(directory/"libunbound/libunbound-8.dll"))
    lib.ub_ctx_create.restype=ctypes.c_void_p
    lib.ub_ctx_config.argtypes=[ctypes.c_void_p,ctypes.c_char_p]
    lib.ub_ctx_delete.argtypes=[ctypes.c_void_p]
    lib.ub_resolve.argtypes=[ctypes.c_void_p,ctypes.c_char_p,ctypes.c_int,ctypes.c_int,ctypes.POINTER(ctypes.POINTER(Result))]
    lib.ub_resolve_free.argtypes=[ctypes.POINTER(Result)]
    lib.ub_version.restype=ctypes.c_char_p
    ctx=lib.ub_ctx_create()
    try:
        code=lib.ub_ctx_config(ctx,str(config).encode())
        if code:pipe.send(dict(error="REFERENCE_CONFIG_ERROR",code=code));return
        result=ctypes.POINTER(Result)()
        code=lib.ub_resolve(ctx,b"probe.example.test.",1,1,ctypes.byref(result))
        if code:pipe.send(dict(error="REFERENCE_RESOLVE_ERROR",code=code));return
        r=result.contents
        pipe.send(dict(reference_version=lib.ub_version().decode(),secure=bool(r.secure),bogus=bool(r.bogus),
            havedata=bool(r.havedata),nxdomain=bool(r.nxdomain),rcode=r.rcode,
            answer_wire_hex=ctypes.string_at(r.answer_packet,r.answer_len).hex(),why_bogus=r.why_bogus.decode(errors="replace") if r.why_bogus else None,
            provenance="external_reference_not_project_V",network_scope="controlled_loopback_independent_iterator"))
        lib.ub_resolve_free(result)
    finally:lib.ub_ctx_delete(ctx);pipe.close()


async def reference(lab,directory,out):
    out=Path(out);out.mkdir(parents=True,exist_ok=True)
    date=datetime.fromtimestamp(lab.signed.now,timezone.utc).strftime("%Y%m%d%H%M%S")
    config=out/"reference.conf"
    with tempfile.NamedTemporaryFile(prefix="dns-reference-root-",suffix=".hints",delete=False) as temp:
        temp.write(b". 3600 IN NS a.root.\na.root. 3600 IN A 127.0.0.10\n");hints_path=Path(temp.name)
    lines=["server:"," use-syslog: no"," verbosity: 0"," do-ip6: no"," do-not-query-localhost: no",
        ' module-config: "validator iterator"'," val-sig-skew-min: 0"," val-sig-skew-max: 0",f" val-override-date: {date}",
        f' root-hints: "{hints_path.as_posix()}"'," trust-anchor-signaling: no"," qname-minimisation: no",
        ' local-zone: "test." nodefault', ' local-zone: "example.test." nodefault',
        ' trust-anchor: ". IN DS '+lab.signed.anchor["ds"][0]+'"']
    config.write_text("\n".join(lines)+"\n",encoding="utf-8")
    # The upstream Windows build uses narrow fopen; use a disposable ASCII temp
    # filename rather than interpreting a Unicode-path open failure as DNSSEC failure.
    with tempfile.NamedTemporaryFile(prefix="dns-reference-",suffix=".conf",delete=False) as temp:
        temp.write(config.read_bytes());temp_path=Path(temp.name)
    if not str(temp_path).isascii():
        temp_path.unlink();return dict(error="REFERENCE_ASCII_TEMP_PATH_UNAVAILABLE")
    context=multiprocessing.get_context("spawn");reader,writer=context.Pipe(duplex=False)
    process=context.Process(target=resolve_worker,args=(str(Path(directory).resolve()),str(temp_path),writer),daemon=True)
    process.start();writer.close();deadline=time.monotonic()+12
    try:
        while time.monotonic()<deadline:
            if await asyncio.to_thread(reader.poll,.05):
                try:return await asyncio.to_thread(reader.recv)
                except EOFError:return dict(error="REFERENCE_PROCESS_EXIT")
        return dict(error="REFERENCE_DEADLINE",provenance="external_reference_not_project_V")
    finally:
        if process.is_alive():process.terminate()
        await asyncio.to_thread(process.join,1)
        if process.is_alive():process.kill();await asyncio.to_thread(process.join,1)
        process.close();reader.close()
        temp_path.unlink(missing_ok=True)
        hints_path.unlink(missing_ok=True)
