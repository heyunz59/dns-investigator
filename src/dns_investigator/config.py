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

    @classmethod
    def load(cls):
        load_dotenv()
        return cls(os.getenv("DEEPSEEK_API_KEY", ""),
                   os.getenv("DEEPSEEK_MODEL", "deepseek-flash"),
                   os.getenv("DEEPSEEK_BASE_URL", "https://api.deepseek.com"),
                   float(os.getenv("MODEL_TIMEOUT", "60")),
                   int(os.getenv("MAX_TOOL_CALLS", "10")))
