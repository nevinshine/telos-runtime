import os
import sys
import yaml
import logging
from typing import List, Optional, Dict, Any, Union
from pydantic import BaseModel, Field, ValidationError, field_validator, AliasChoices, AnyHttpUrl, RootModel
from pydantic_settings import BaseSettings, SettingsConfigDict

# Attempt to use rich for beautiful error formatting
try:
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    console = Console()
except ImportError:
    console = None

log = logging.getLogger('telos.config')

class ExecutionPolicy(BaseModel):
    default_mode: str = Field(default="enforce", pattern="^(enforce|audit)$")
    safe_binaries: List[str] = Field(default_factory=list)

class NetworkPolicy(BaseModel):
    always_allowed: List[str] = Field(default_factory=list)

class FilesystemPolicy(BaseModel):
    sensitive_paths: List[str] = Field(default_factory=list)

class PolicyConfig(BaseModel):
    execution: ExecutionPolicy = Field(default_factory=ExecutionPolicy)
    network: NetworkPolicy = Field(default_factory=NetworkPolicy)
    filesystem: FilesystemPolicy = Field(default_factory=FilesystemPolicy)

class CortexSettings(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix='TELOS_CORTEX_', 
        env_file='.env', 
        extra='ignore',
        validate_assignment=True
    )

    # Required Environment Variables with Alias Choices
    database_url: str = Field(..., validation_alias=AliasChoices('DATABASE_URL', 'TELOS_CORTEX_DATABASE_URL'))
    api_key: str = Field(..., validation_alias=AliasChoices('API_KEY', 'TELOS_CORTEX_API_KEY'))
    auth_token: str = Field(..., validation_alias=AliasChoices('AUTH_TOKEN', 'TELOS_CORTEX_AUTH_TOKEN'))
    
    # Server Settings
    port: int = Field(default=50051, ge=1, le=65535)
    bind_host: str = "127.0.0.1"
    socket_path: str = "/var/run/telos.sock"
    log_path: Optional[str] = None

    @field_validator('database_url')
    @classmethod
    def validate_db_url(cls, v: str) -> str:
        if not any(v.startswith(prefix) for prefix in ['postgres://', 'postgresql://', 'sqlite://', 'mysql://']):
            raise ValueError("DATABASE_URL must start with a valid scheme (postgres, sqlite, etc.)")
        return v

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
        # Fallback to standard logging if rich is missing
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
        if args.port: env_overrides['port'] = args.port
        if args.bind_host: env_overrides['bind_host'] = args.bind_host
        if args.socket: env_overrides['socket_path'] = args.socket
        if args.auth_token: env_overrides['auth_token'] = args.auth_token

        settings = CortexSettings(**env_overrides)
    except ValidationError as e:
        _print_fancy_errors("Startup Configuration Failed", e.errors())
        sys.exit(1)

    policy = load_policy(args.policy)
    return settings, policy
