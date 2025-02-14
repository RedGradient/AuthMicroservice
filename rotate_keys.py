import json
import os.path
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from pydantic import BaseModel

KEYS_DIR_PATH: Path = Path("keys")
PUBLIC_KEYS_PATH: Path = KEYS_DIR_PATH / "public_keys.json"

class KeyStore(BaseModel):
    class Key(BaseModel):
        id: str
        created_at: str
    active_key: str | None
    keys: list[Key]

    @classmethod
    def load(cls) -> "KeyStore":
        # Create 'public_keys.json' if not exists
        if not os.path.exists(PUBLIC_KEYS_PATH):
            initial_data: dict[str, Any] = {
                "active_key": None,
                "keys": []
            }
            with open(PUBLIC_KEYS_PATH, "w") as f:
                json.dump(initial_data, f)

        with open(PUBLIC_KEYS_PATH, "r") as f:
            data = json.load(f)

        public_keys = cls.model_validate(data)
        return public_keys

    def save(self) -> None:
        with open(PUBLIC_KEYS_PATH, "w") as f:
            json_data = self.model_dump_json(indent=4)
            f.write(json_data)

    def __enter__(self) -> "KeyStore":
        return self

    def __exit__(self, exc_type: Any, exc_value: Any, traceback: Any) -> None:
        self.save()

        self.active_key = None
        self.keys.clear()


def rotate_keys() -> None:
    key_id = datetime.now().strftime("%d%m%Y%H%M%S")
    generate_key_pair(key_id)

    with KeyStore.load() as public_keys:
        public_keys.active_key = key_id
        public_keys.keys.append(KeyStore.Key(id=key_id, created_at=datetime.now().isoformat()))

def remove_expired_keys() -> None:
    now = datetime.now()
    expiry_time = timedelta(minutes=30)

    with KeyStore.load() as public_keys:
        public_keys.keys = list(filter(
            lambda key: datetime.fromisoformat(key.created_at) > (now - expiry_time),
            public_keys.keys
        ))

def generate_key_pair(key_id: str) -> None:
    private_key_path = KEYS_DIR_PATH / f"{key_id}.pem"
    public_key_path = KEYS_DIR_PATH / f"{key_id}.pub.pem"

    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048, backend=default_backend())
    public_key = private_key.public_key()

    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    with open(private_key_path, "wb") as private_file:
        private_file.write(private_pem)
    with open(public_key_path, "wb") as public_file:
        public_file.write(public_pem)


if __name__ == "__main__":
    rotate_keys()
    # remove_expired_keys()
