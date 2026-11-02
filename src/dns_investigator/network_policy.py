"""Shared numeric-IP classification; each protocol retains its own authorization."""
import ipaddress

def numeric(value):
    if '%' in str(value):raise ValueError('Scoped IP not supported')
    ip=ipaddress.ip_address(value)
    return getattr(ip,'ipv4_mapped',None) or ip

def public(ip):
    return (ip.is_global and not ip.is_reserved and not ip.is_loopback and not ip.is_link_local
            and not ip.is_multicast and not ip.is_unspecified
            and not (isinstance(ip,ipaddress.IPv6Address) and (ip.sixtofour or ip.teredo)))

def networks(values):return tuple(ipaddress.ip_network(v,strict=True) for v in values)

def tcp_address(value,allowed):
    ip=numeric(value)
    special=(ip.is_link_local or ip.is_multicast or ip.is_unspecified or
        str(ip) in {'169.254.169.254','100.100.100.200','fd00:ec2::254'} or
        isinstance(ip,ipaddress.IPv6Address) and (ip.sixtofour or ip.teredo or
            ip in ipaddress.ip_network('64:ff9b::/96') or ip in ipaddress.ip_network('64:ff9b:1::/48')))
    if special or not(public(ip) or any(ip in n for n in allowed)):raise ValueError('TCP destination not authorized')
    return str(ip)
