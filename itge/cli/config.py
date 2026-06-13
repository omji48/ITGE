"""
CLI configuration and utilities.
"""

from __future__ import annotations

import json
import logging
import sys
from pathlib import Path

from pydantic import BaseModel, Field
from rich.console import Console
from rich.logging import RichHandler

console = Console()


class ITGEConfig(BaseModel):
    """Runtime configuration for the CLI and API."""

    neo4j_uri: str = Field(default="bolt://localhost:7687")
    neo4j_user: str = Field(default="neo4j")
    neo4j_password: str = Field(default="password")

    log_level: str = Field(default="INFO")
    log_file: str | None = Field(default=None)

    output_dir: Path = Field(default=Path("./itge_output"))

    default_max_hops: int = Field(default=10)
    default_max_paths: int = Field(default=50)


def setup_logging(level: str = "INFO", log_file: str | None = None) -> None:
    logging.basicConfig(
        level=level,
        format="%(message)s",
        datefmt="[%X]",
        handlers=[RichHandler(console=console, rich_tracebacks=True)],
    )

    if log_file:
        file_handler = logging.FileHandler(log_file)
        file_handler.setFormatter(
            logging.Formatter("%(asctime)s - %(name)s - %(levelname)s - %(message)s")
        )
        logging.getLogger().addHandler(file_handler)


def load_config(config_file: Path | None = None) -> ITGEConfig:
    if config_file and config_file.exists():
        return ITGEConfig(**json.loads(config_file.read_text(encoding="utf-8")))
    return ITGEConfig()


def save_config(config: ITGEConfig, config_file: Path) -> None:
    config_file.parent.mkdir(parents=True, exist_ok=True)
    config_file.write_text(
        json.dumps(config.model_dump(), indent=2, default=str),
        encoding="utf-8",
    )


def handle_error(error: Exception, exit_code: int = 1) -> None:
    console.print(f"[bold red]Error:[/bold red] {error}")
    logging.exception("Detailed error information:")
    sys.exit(exit_code)


def success(message: str) -> None:
    console.print(f"[bold green][OK][/bold green] {message}")


def info(message: str) -> None:
    console.print(f"[bold blue][INFO][/bold blue] {message}")


def warning(message: str) -> None:
    console.print(f"[bold yellow][WARN][/bold yellow] {message}")


def error(message: str) -> None:
    console.print(f"[bold red][ERR][/bold red] {message}")
