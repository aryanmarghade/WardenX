import pytest
import os
import sys
from pathlib import Path

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

@pytest.fixture(autouse=True)
def mock_db_path(tmp_path, mocker):
    """Mocks database path to use a temporary file for tests."""
    temp_db = tmp_path / "test_wardenx.db"
    mocker.patch('database.get_db_path', return_value=temp_db)
    return temp_db
