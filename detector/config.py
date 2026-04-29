import yaml, os

_cfg = None

def get() -> dict:
    global _cfg
    if _cfg is None:
        path = os.environ.get("CONFIG_PATH", "/app/config.yaml")
        with open(path) as f:
            _cfg = yaml.safe_load(f)
    return _cfg
