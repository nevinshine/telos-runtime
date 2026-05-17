import os
import sys
import yaml
import logging
from typing import List, Optional, Dict, Any

from pydantic import BaseModel, Field, ValidationError, field_validator, AliasChoices
from pydantic_settings import BaseSettings, SettingsConfigDict

try:
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    console = Console()
except ImportError:
    console = None

log = logging.getLogger('telos.config')

class TaintPolicy(BaseModel):
    max_taint_for_exec: int = Field(default=2)
    max_taint_for_network: int = Field(default=3)
    decay_interval: int = Field(default=300)

class AgentPolicy(BaseModel):
    auto_register_patterns: List[str] = Field(default_factory=list)
    max_agents: int = Field(default=10)

class NetworkPolicy(BaseModel):
    default_action: str = Field(default="deny")
    always_allowed: List[str] = Field(default_factory=list)
    blocked: List[str] = Field(default_factory=list)

class FilesystemPolicy(BaseModel):
    sensitive_paths: List[str] = Field(min_length=1) # Required to have at least one
    allowed_paths: List[str] = Field(default_factory=list)

class DetectionPolicy(BaseModel):
    high_severity_keywords: List[str] = Field(default_factory=list)
    critical_keywords: List[str] = Field(default_factory=list)

class LoggingPolicy(BaseModel):
    level: str = Field(default="INFO")
    audit_taints: bool = Field(default=True)
    audit_blocks: bool = Field(default=True)

class MirageHoneyFile(BaseModel):
    path: str
    payload: str

class MiragePolicy(BaseModel):
    enabled: bool = Field(default=True)
    honey_files: List[MirageHoneyFile] = Field(default_factory=list)

class PolicyConfig(BaseModel):
    taint: TaintPolicy = Field(default_factory=TaintPolicy)
    agent: AgentPolicy = Field(default_factory=AgentPolicy)
    network: NetworkPolicy = Field(default_factory=NetworkPolicy)
    filesystem: FilesystemPolicy
    detection: DetectionPolicy = Field(default_factory=DetectionPolicy)
    logging: LoggingPolicy = Field(default_factory=LoggingPolicy)
    mirage: MiragePolicy = Field(default_factory=MiragePolicy)


class CortexSettings(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix='TELOS_CORTEX_', 
        env_file='.env', 
        extra='ignore',
        validate_assignment=True
    )
    
    auth_token: str = Field(..., validation_alias=AliasChoices('AUTH_TOKEN', 'TELOS_CORTEX_AUTH_TOKEN'))
    
    # Server Settings
    port: int = Field(default=50051, ge=1, le=65535)
    bind_host: str = "127.0.0.1"
    socket_path: str = "/var/run/telos.sock"


def _print_fancy_errors(title: str, errors: List[Dict[str, Any]]):
    """Print production-grade error report using Rich."""
    if console:
        table = Table(title=f"[bold red]{title}[/bold red]", show_header=True, header_style="bold magenta")
        table.add_column("Field Location", style="cyan")
        table.add_column("Error Message", style="white")
        table.add_column("Input Given", style="dim")
        for error in errors:
            loc = " -> ".join(str(l) for l in error['loc'])
            msg = error['msg']
            inp = str(error.get('input', 'N/A'))
            table.add_row(loc, msg, inp)
        
        console.print("\n")
        console.print(Panel(table, border_style="red", expand=False))
        console.print("[bold yellow]Action Required:[/bold yellow] Please update your [bold cyan].env[/bold cyan] or [bold cyan]policy.yaml[/bold cyan] and restart.\n")
    else:
        log.error(f"--- {title} ---")
        for error in errors:
            loc = " -> ".join(str(l) for l in error['loc'])
            log.error(f"  [!] {loc}: {error['msg']}")

def load_policy(policy_path: str) -> PolicyConfig:
    """Load and validate policy.yaml."""
    if not os.path.exists(policy_path):
        _print_fancy_errors("Policy File Missing", [{
            "loc": ["policy_file"],
            "msg": f"The required policy file was not found at {policy_path}",
            "input": policy_path
        }])
        sys.exit(1)
    
    try:
        with open(policy_path, 'r') as f:
            data = yaml.safe_load(f) or {}
            return PolicyConfig(**data)
    except yaml.YAMLError as e:
        log.error(f"CRITICAL: YAML Syntax Error in {policy_path}: {e}")
        sys.exit(1)
    except ValidationError as e:
        _print_fancy_errors("Invalid Policy Configuration", e.errors())
        sys.exit(1)

def load_config(args: Any) -> tuple[CortexSettings, PolicyConfig]:
    """
    Production-grade configuration loader with fail-fast validation.
    """
    try:
        env_overrides = {}
        if getattr(args, 'port', None): env_overrides['port'] = args.port
        if getattr(args, 'bind_host', None): env_overrides['bind_host'] = args.bind_host
        if getattr(args, 'socket', None): env_overrides['socket_path'] = args.socket
        if getattr(args, 'auth_token', None): env_overrides['auth_token'] = args.auth_token
        
        settings = CortexSettings(**env_overrides)
    except ValidationError as e:
        _print_fancy_errors("Startup Configuration Failed", e.errors())
        sys.exit(1)
        
    policy = load_policy(args.policy)
    return settings, policy
