import pytest

from passwordmanager.core.crypto import KdfParams
from passwordmanager.core.vault import Vault

MASTER = "correct horse battery"


@pytest.fixture
def fast_params():
    # Minimal Argon2 cost so the test suite runs in milliseconds.
    return KdfParams(time_cost=1, memory_cost=8, parallelism=1)


@pytest.fixture
def vault_path(tmp_path):
    return tmp_path / "vault.bin"


@pytest.fixture
def vault(vault_path, fast_params):
    return Vault.create(vault_path, MASTER, fast_params)
