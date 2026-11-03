# Development

Clone the candidate branch shown in README, create a virtual environment and install `python -m pip install -e ".[web,dev]"`. requirements.txt is the pinned core input; web/dev extras are in pyproject.toml. requirements-web/dev.txt are repository-root compatibility installers. requirements-lock.txt is an environment constraints snapshot, not a universal hash lock.

Run `python -m pytest -q`, `python scripts/check_repository.py` and `python scripts/check_public.py`. Build `python -m pip wheel --no-deps . --wheel-dir dist`; after editable installation run `python scripts/check_installation.py --wheel-dir dist --restore-editable --output results/runs/installation.json`. dist must contain exactly one project wheel. Checks run outside the checkout and verify both CLI entries, strict JSON and every module/asset.

For browser checks, install web, run `python -m scripts.prepare_web_demos`, start `dns-investigator-web`, then run `python scripts/check_web_browser.py`. Outputs stay under ignored results/runs. Install optional Playwright using `python -m pip install playwright`; Linux needs `python -m playwright install chromium`. Explicit --live performs paid/public checks and is never CI's default.

Version has one source, src/dns_investigator/__init__.py. Confirm installed metadata using `python -c "from importlib.metadata import version; print(version('dns-investigator'))"`. CLI has no --version flag; logs record app version.

src contains installed runtime code; tests/fixtures and data/fixtures contain controlled inputs. evaluation contains reusable harnesses/scoring definitions, not generated results. Paths inside fixture provenance identify archived originals; tests do not open those paths.
