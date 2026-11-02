import os
from dataclasses import dataclass
from dotenv import load_dotenv


@dataclass
class Config:
    api_key: str
    model: str = "deepseek-flash"
    base_url: str = "https://api.deepseek.com"
    model_timeout: float = 60
    max_tool_calls: int = 10
    dns_query_budget: int = 32
    dns_tool_timeout: float = 20
    max_auth_servers: int = 2
    dns_resolvers: tuple = (None, "1.1.1.1", "8.8.8.8")
    http_allowed_origins: tuple = ()
    http_allowed_networks: tuple = ()
    tcp_allowed_networks: tuple = ()

    def __post_init__(self):
        import ipaddress
        for cidr in self.tcp_allowed_networks:ipaddress.ip_network(cidr,strict=True)
        if not 1 <= self.dns_query_budget <= 128 or not 1 <= self.dns_tool_timeout <= 60:
            raise ValueError("DNS budget/timeout out of range")
        if not 1 <= len(self.dns_resolvers) <= 4:
            raise ValueError("Configure 1 to 4 recursive resolver identities")
        for resolver in self.dns_resolvers:
            if resolver is not None:
                ipaddress.ip_address(resolver)

    @classmethod
    def load(cls):
        load_dotenv()
        return cls(os.getenv("DEEPSEEK_API_KEY", ""),
                   os.getenv("DEEPSEEK_MODEL", "deepseek-flash"),
                   os.getenv("DEEPSEEK_BASE_URL", "https://api.deepseek.com"),
                   float(os.getenv("MODEL_TIMEOUT", "60")),
                   int(os.getenv("MAX_TOOL_CALLS", "10")),
                   int(os.getenv("DNS_QUERY_BUDGET", "32")),
                   float(os.getenv("DNS_TOOL_TIMEOUT", "20")),
                   min(3,max(1,int(os.getenv("MAX_AUTH_SERVERS", "2")))),
                   tuple(None if x.strip()=="system" else x.strip() for x in os.getenv("DNS_RESOLVERS","system,1.1.1.1,8.8.8.8").split(",") if x.strip()),
                   tuple(x.strip() for x in os.getenv("HTTP_ALLOWED_ORIGINS","").split(",") if x.strip()),
                   tuple(x.strip() for x in os.getenv("HTTP_ALLOWED_NETWORKS","").split(",") if x.strip()),
                   tuple(x.strip() for x in os.getenv("TCP_ALLOWED_NETWORKS","").split(",") if x.strip()))
