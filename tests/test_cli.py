from pathlib import Path
import sys
import pytest
from dns_investigator.main import main


def test_missing_target_prompts_then_runs_offline(monkeypatch, capsys):
    fixture = Path(__file__).resolve().parents[1] / "data/fixtures/C2.json"
    monkeypatch.setattr(sys, "argv", ["dns-investigator", "请帮我调查", "--tools-only", "--fixture", str(fixture)])
    prompts = []
    def answer(prompt):
        prompts.append(prompt)
        return "example.com"
    monkeypatch.setattr("builtins.input", answer)
    # This case represents an interactive terminal; piped/JSON calls must not prompt.
    monkeypatch.setattr(sys.stdin,'isatty',lambda:True)
    with pytest.raises(SystemExit) as result:
        main()
    assert result.value.code == 0 and len(prompts) == 1
    assert "NXDOMAIN" in capsys.readouterr().out


def test_invalid_url_is_rejected_before_model(monkeypatch, capsys):
    monkeypatch.setattr(sys, "argv", ["dns-investigator", "调查", "--target", "https://user:password@example.com"])
    with pytest.raises(SystemExit) as result:
        main()
    assert result.value.code == 2
    assert "输入错误" in capsys.readouterr().out
