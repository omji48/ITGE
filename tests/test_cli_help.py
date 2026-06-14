from typer.testing import CliRunner

from itge.cli.main import app


def test_cli_help_lists_doctor_and_serve_api() -> None:
    runner = CliRunner()
    result = runner.invoke(app, ["--help"])

    assert result.exit_code == 0
    assert "doctor" in result.stdout
    assert "serve-api" in result.stdout
