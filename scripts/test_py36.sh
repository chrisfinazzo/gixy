#!/bin/bash
# Run full test suite with Python 3.6 to catch compatibility issues
# This hook is optional - it only runs if $HOME/.virtualenvs/gixy-py36 exists

PY36_VENV="$HOME/.virtualenvs/gixy-py36"

if [ ! -d "$PY36_VENV" ]; then
    echo "⚠️  Python 3.6 venv not found at $PY36_VENV - skipping Py3.6 tests"
    echo "   To set up: pyenv install 3.6.15 && python3.6 -m venv $PY36_VENV"
    exit 0
fi

echo "🐍 Running full test suite with Python 3.6..."

# Run full test suite with Python 3.6
"$PY36_VENV/bin/python" -m pytest tests/ -v --tb=short 2>&1

exit_code=$?

if [ $exit_code -eq 0 ]; then
    echo "✅ Python 3.6 tests passed"
else
    echo "❌ Python 3.6 tests FAILED"
fi

exit $exit_code
