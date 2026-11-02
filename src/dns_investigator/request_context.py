"""Conservative task focus, never a source of measurement or authorization."""
import re


def context(text,target,kind):
    # Quoted claims and explicit negation do not establish a positive focus.
    clean=re.sub(r'"[^"\n]*"|“[^”\n]*”|「[^」\n]*」|\'[^\'\n]*\'', '',text)
    token=lambda name:r'(?<![A-Za-z0-9_])'+name+r'(?![A-Za-z0-9_])'
    patterns={'TCP/Network Transport':token('TCP'),'HTTP':token('HTTPS?'),'TLS':token('TLS')+'|证书',
              'DNSSEC':token('DNSSEC'),'Recursive DNS':token('DNS')+'|解析'}
    layers=[];negated=False
    for layer,pat in patterns.items():
        for m in re.finditer(pat,clean,re.I):
            prefix=clean[max(0,m.start()-16):m.start()]
            if re.search(r'(?:不(?:是|要|必|关注|检查|排查)?|无需|忽略|not|ignore|without)\s*(?:只)?(?:查|看|检查|关注|排查)?\s*$',prefix,re.I):negated=True;continue
            layers.append(layer)
    layers=list(dict.fromkeys(layers))
    ambiguous=len(layers)!=1
    return dict(target=target.domain,url=target.url,port=target.port,request_kind=kind,
        focus_layers=layers if not ambiguous else [],ambiguous=ambiguous,
        intent_source='explicit_user_statement' if not ambiguous else 'ambiguous_or_unspecified',
        interpretation='仅用于展示相关性；多个层、否定或引用无法可靠消歧时保持未知。',negated_mentions=negated)
