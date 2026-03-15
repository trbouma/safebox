import pathlib

from pydantic import AnyHttpUrl, BaseModel
from pydantic_settings import BaseSettings

from typing import ClassVar, List, Optional, Union, Dict, Tuple

import os
from pathlib import Path

from monstr.encrypt import Keys
import oqs

# Project Directories
ROOT = pathlib.Path(__file__).resolve().parent.parent


def _default_currency_csv() -> str:
    project_csv = ROOT / "setup" / "currency.csv"
    container_csv = Path("/app/setup/currency.csv")

    if project_csv.exists():
        return str(project_csv)
    if container_csv.exists():
        return str(container_csv)
    return str(project_csv)


def _default_secret_dir() -> Path:
    container_secret_dir = Path("/run/secrets")
    project_secret_dir = ROOT / "data" / "secrets"

    if container_secret_dir.exists() and os.access(container_secret_dir, os.W_OK):
        return container_secret_dir
    return project_secret_dir


def _default_secret_file(name: str) -> str:
    return str(_default_secret_dir() / name)





class Settings(BaseSettings):
    APP_ENV: str = "development"
    HOME_RELAY: str = 'wss://relay.getsafebox.app'
    HOME_MINT: str= 'https://mint.getsafebox.app'      
    SERVICE_NAME: str = 'Safebox'
    SERVICE_TAG_LINE: str = 'Your Funds. Your Records'
    SERVICE_SECRET_KEY: str|None = None
    SERVICE_RELAY_DB: str = "data/relay.db"
    TZ: str = "America/New_York"
    ALGORITHM: str = "HS256"
    PQC_SIGALG: str = "ML-DSA-44"
    PQC_KEMALG: str = "ML-KEM-512"
    DATABASE: str = "sqlite:///data/database.db"  
    DB_POOL_SIZE: int = 10
    DB_MAX_OVERFLOW: int = 20
    DB_POOL_RECYCLE_SECONDS: int = 1800
    DB_POOL_TIMEOUT_SECONDS: int = 30
    RELAYS: List = ['wss://relay.getsafebox.app']
    PUBLIC_RELAYS: List = ['wss://relay.getsafebox.app', 'wss://relay.damus.io', 'wss://relay.primal.net']
    ECASH_RELAYS: List = ['wss://relay.getsafebox.app']
    MINTS: List = ['https://mint.getsafebox.app']
    IP_INFO_TOKEN: str = "notset"
    NFC_ECASH_CLEARING: bool = True
    NFC_DEFAULT: List = ["Badge","Member"]
    LOCAL_RELAY_PORT: int = 8735
    TOKEN_EXPIRES_WEEKS: int = 4
    TOKEN_EXPIRES_HOURS: int = 8
    SESSION_AGE_DAYS: int = 30
    LOGGING_LEVEL: int = 10
    SUPPORTED_CURRENCIES: List =['SAT','CAD','USD','EUR','GBP','JPY','INR']
    BRANDING: str = "Get SafeBox"
    BRANDING_MESSAGE: str = "Control your personal funds and data."
    BRANDING_RETRY: str = "Whoops! Let's try that again!"
    BRANDING_DIR: str = "branding"
    INVITE_CODES: List = ["alpha", "rektuser", "earlyaccess"]
    AUTH_RELAYS: List = ['wss://relay.getsafebox.app']
    NWC_SERVICE: bool = False
    AGENT_RATE_LIMIT_ENABLED: bool = True
    AGENT_RPM: int = 60
    AGENT_BURST: int = 20
    AGENT_ONBOARD_RPM: int = 10
    AGENT_ONBOARD_BURST: int = 5
    NWC_RELAYS: List = ['wss://relay.getsafebox.app']
    NWC_FILTER_REFRESH_SECONDS: int = 15
    NWC_SUBSCRIBE_WAIT_SECONDS: int = 5
    NFC_REQUESTER_NONCE_TTL_SECONDS: int = 300
    NFC_REQUESTER_NONCE_RETENTION_SECONDS: int = 86400
    NFC_REQUESTER_SERVICE_ALLOWLIST: List[str] = []
    RECORD_REQUESTER_SIGNATURE_REQUIRED: bool = False
    RECORD_REQUESTER_SERVICE_ALLOWLIST: List[str] = []
    TRANSMITTAL_RELAYS: List = ['wss://relay.getsafebox.app']
    DM_RELAYS: List = ['wss://relay.getsafebox.app']
    REFRESH_CURRENCY_INTERVAL: int = 3600
    TRANSMITTAL_KIND: int = 21060
    AUTH_KIND: int = 21061
    CREDENTIAL_TRANSMITTAL_KIND: int = 21062
    CREDENTIAL_TRANSMITTAL_RELAYS: List = ['wss://relay.getsafebox.app']
    RECORD_TRANSMITTAL_KIND: int = 21062
    RECORD_TRANSMITTAL_RELAYS: List = ['wss://relay.getsafebox.app']
    CURRENCY_CSV: str = _default_currency_csv()
    WOT_RELAYS: List = ['wss://wotr.relatr.xyz','wss://nip85.brainstorm.world']
    LISTEN_TIMEOUT: int = 120
    ECASH_LISTEN_TIMEOUT: int = 120
    BLOSSOM_SERVERS: List[str] = ['https://blossom.getsafebox.app']
    BLOSSOM_HOME_SERVER: str = 'https://blossom.getsafebox.app'
    BLOSSOM_XFER_SERVER: str = 'https://blossomx.getsafebox.app'
    CORS_ALLOW_ORIGINS: List[str] = [
        "https://getsafebox.app",
        "https://www.getsafebox.app",
        "https://openbrowserclaw.com",
        "https://www.openbrowserclaw.com",
        "http://localhost:7375",
        "http://127.0.0.1:7375",
    ]
    COOKIE_SECURE: bool = True
    COOKIE_SAMESITE: str = "Lax"
    CSRF_COOKIE_NAME: str = "csrf_token"

    # Offer and Grant Kinds
    # Numbering Convention is the offer is odd-number and consecutive even-number is the grant
    # Can be calculated but flexible with defining both offer and grant kinds
    OFFER_KINDS: List =     [  
                            [34103, "Shared Note", ["share"]], 
                            [34039, "Community", ["Name", "Family", "Membership","Library Card","Training", "Committee", "Qualification","Title", "Honorific"]], 
                            [34037, "Receipt"],
                            [34001, "Badge", ["Access", "ID"]],
                            [34035, "Contact"],
                            [34101, "Business Card"],                            
                            [34029,"Pass"],
                            [32225,"Health"], 
                            [32229, "Prescription"],  
                            [32231, "Immunization"],    
                            [34003, "Payment Card"],
                            [34005, "Travel Document"],
                            [34007, "Membership"],
                            [34009, "Gift Card"],
                            [34011, "Coupon"],
                            [34013, "Event Ticket"],                            
                            [34017, "Transit Card"],                            
                            [34019, "Educational Diploma"],
                            [34021, "Official Documentation"],
                            [34023, "Insurance"],
                            [34025, "Recipe"],
                            [34031, "Voucher"],  
                            [34033, "Letter"],
                            [34035, "Emergency"],
                            [34037, "Negotiable Cargo Document",["Bill of Lading","Warehouse Receipt"]],
                            [34041, "Skilled Trade",["Electrician","Plumber", "Welder"]]
                                                      
                            
                        ]  
 
    GRANT_KINDS: List =     [  
                            [34104, "Shared Note", ["share"]], 
                            [34040, "Community",["Name", "Family", "Membership", "Library Card", "Training", "Committee", "Qualification", "Title", "Honorific"]],
                            [34038, "Receipt"],
                            [34002, "Badge", ["Access", "ID"]],
                            [34036, "Contact"],
                            [34102, "Business Card"],                            
                            [34030,"Pass", ["Admission","Boarding"]],
                            [32226,"Health"], 
                            [32230, "Prescription"],  
                            [32232, "Immunization"],    
                            [34004, "Payment Card"],
                            [34006, "Travel Document"],
                            [34008, "Membership"],
                            [34010, "Gift Card"],
                            [34012, "Coupon"],
                            [34014, "Event Ticket"],                            
                            [34018, "Transit Card"],                            
                            [34020, "Educational Diploma"],
                            [34022, "Official Documentation"],
                            [34024, "Insurance"],
                            [34026, "Recipe"],
                            [34032, "Voucher"],
                            [34034, "Letter"],
                            [34036, "Emergency", ["medical","contact"]],    
                            [34038, "Negotiable Cargo Document"], 
                            [34042, "Skilled Trade"]                        
                            
                            
                        ] 

    WALLET_SWAP_MODE: bool = False

    class Config:
        env_file = '.env'
        env_file_encoding ='utf-8'
        case_sensitive = True
    EMERGENCY_INFO: str =  """
Medical Emergency Card

Full Name:  
    _________________________________

Date of Birth:  
    _________________________________

Emergency Contact(s):  
    - Name: _________________________  
      Phone: ________________________
    - Name: _________________________  
      Phone: ________________________

Medical Conditions:  
    _________________________________  
    _________________________________

Allergies (medications, food, etc.):  
    _________________________________  
    _________________________________

Medications (include dosage if known):  
    _________________________________  
    _________________________________

Primary Physician:  
    Name: ___________________________  
    Phone: __________________________

Blood Type:  
    _________________________________

Health Insurance Info (optional):  
    Provider: _______________________  
    Policy #: _______________________

Other Notes (e.g., pacemaker, mobility needs):  
    _________________________________  
    _________________________________
"""

class modeEventKind(BaseModel):
    mode: str
    kind: int

class mapEventKind(BaseModel):
    mapping: List [modeEventKind]


settings = Settings()

class ConfigWithFallback(BaseSettings):
    SERVICE_NSEC: str = "notset"
    SERVICE_NPUB: str = "notset"
    NWC_NSEC: str = "notset"
    PQC_SIG_SECRET_KEY: str = "notset"
    PQC_SIG_PUBLIC_KEY: str = "notset"
    PQC_KEM_PUBLIC_KEY: str = "notset"
    PQC_KEM_SECRET_KEY: str = "notset"
    SERVICE_NSEC_FILE: str = _default_secret_file("service_nsec")
    SERVICE_NPUB_FILE: str = _default_secret_file("service_npub")
    NWC_NSEC_FILE: str = _default_secret_file("nwc_nsec")
    PQC_SIG_SECRET_KEY_FILE: str = _default_secret_file("pqc_sig_secret_key")
    PQC_SIG_PUBLIC_KEY_FILE: str = _default_secret_file("pqc_sig_public_key")
    PQC_KEM_SECRET_KEY_FILE: str = _default_secret_file("pqc_kem_secret_key")
    PQC_KEM_PUBLIC_KEY_FILE: str = _default_secret_file("pqc_kem_public_key")
    SECRET_BOOTSTRAP_MODE: bool = False

    class Config:
        case_sensitive = False

    PRIVATE_SECRET_FILE_ATTRS: ClassVar[Dict[str, str]] = {
        "SERVICE_NSEC": "SERVICE_NSEC_FILE",
        "NWC_NSEC": "NWC_NSEC_FILE",
        "PQC_SIG_SECRET_KEY": "PQC_SIG_SECRET_KEY_FILE",
        "PQC_KEM_SECRET_KEY": "PQC_KEM_SECRET_KEY_FILE",
    }
    COMPANION_FILE_ATTRS: ClassVar[Dict[str, str]] = {
        "SERVICE_NPUB": "SERVICE_NPUB_FILE",
        "PQC_SIG_PUBLIC_KEY": "PQC_SIG_PUBLIC_KEY_FILE",
        "PQC_KEM_PUBLIC_KEY": "PQC_KEM_PUBLIC_KEY_FILE",
    }

    # ---- key generation helpers ----

    @staticmethod
    def _gen_nostr_keys() -> Dict[str, str]:
        k = Keys()
        return {
            "SERVICE_NSEC": k.private_key_bech32(),
            "SERVICE_NPUB": k.public_key_bech32(),
        }

    @staticmethod
    def _gen_nwc_key() -> Dict[str, str]:
        k = Keys()
        return {
            "NWC_NSEC": k.private_key_bech32(),
        }

    @staticmethod
    def _gen_pqc_sig_keys() -> Dict[str, str]:
        signer = oqs.Signature(settings.PQC_SIGALG)
        pq_sig_pubkey = signer.generate_keypair()
        sig_secret_key = signer.export_secret_key()
        return {
            "PQC_SIG_SECRET_KEY": sig_secret_key.hex(),
            "PQC_SIG_PUBLIC_KEY": pq_sig_pubkey.hex(),
        }

    @staticmethod
    def _gen_pqc_kem_keys() -> Dict[str, str]:
        kem = oqs.KeyEncapsulation(settings.PQC_KEMALG)
        kem_public_key = kem.generate_keypair()
        kem_secret_key = kem.export_secret_key()
        return {
            "PQC_KEM_SECRET_KEY": kem_secret_key.hex(),
            "PQC_KEM_PUBLIC_KEY": kem_public_key.hex(),
        }

    @classmethod
    def _gen_missing_values(cls, missing: set[str]) -> Dict[str, str]:
        """
        Generate only what is needed.
        Note: for paired keys we generate the pair if either is missing.
        """
        generated: Dict[str, str] = {}

        # Nostr pair
        if {"SERVICE_NSEC", "SERVICE_NPUB"} & missing:
            generated.update(cls._gen_nostr_keys())

        # NWC key
        if "NWC_NSEC" in missing:
            generated.update(cls._gen_nwc_key())

        # Signature pair
        if {"PQC_SIG_SECRET_KEY", "PQC_SIG_PUBLIC_KEY"} & missing:
            generated.update(cls._gen_pqc_sig_keys())

        # KEM pair
        if {"PQC_KEM_SECRET_KEY", "PQC_KEM_PUBLIC_KEY"} & missing:
            generated.update(cls._gen_pqc_kem_keys())

        # Return only the keys that were actually missing (to avoid overwriting existing file values)
        return {k: v for k, v in generated.items() if k in missing}

    # ---- .conf file helpers ----

    @staticmethod
    def _read_text_secret(path: str | Path) -> str | None:
        secret_path = Path(path)
        if not secret_path.exists() or not secret_path.is_file():
            return None

        value = secret_path.read_text(encoding="utf-8").strip()
        return value or None

    @staticmethod
    def _write_text_secret(path: str | Path, value: str) -> None:
        secret_path = Path(path)
        secret_path.parent.mkdir(parents=True, exist_ok=True)
        secret_path.write_text(f"{value}\n", encoding="utf-8")
        try:
            secret_path.chmod(0o600)
        except OSError:
            pass

    @staticmethod
    def _secret_file_exists(path: str | Path) -> bool:
        return ConfigWithFallback._read_text_secret(path) not in (None, "", "notset")

    @classmethod
    def _get_effective_field_value(cls, field_name: str, kwargs: Dict[str, object] | None = None) -> object:
        if kwargs and field_name in kwargs:
            return kwargs[field_name]
        if field_name in os.environ:
            raw_value = os.environ[field_name]
            field_info = cls.model_fields[field_name]
            if field_info.annotation is bool:
                return str(raw_value).strip().lower() in {"1", "true", "yes", "on"}
            return raw_value
        return cls.model_fields[field_name].default

    @classmethod
    def _get_private_secret_file_map(cls, kwargs: Dict[str, object] | None = None) -> Dict[str, str]:
        return {
            secret_name: str(cls._get_effective_field_value(file_attr, kwargs))
            for secret_name, file_attr in cls.PRIVATE_SECRET_FILE_ATTRS.items()
        }

    @classmethod
    def _get_present_secret_files(cls, kwargs: Dict[str, object] | None = None) -> Dict[str, bool]:
        return {
            secret_name: cls._secret_file_exists(secret_path)
            for secret_name, secret_path in cls._get_private_secret_file_map(kwargs).items()
        }

    @classmethod
    def _load_private_values_from_secret_files(cls, kwargs: Dict[str, object] | None = None) -> Dict[str, str]:
        values: Dict[str, str] = {}
        for secret_name, secret_path in cls._get_private_secret_file_map(kwargs).items():
            secret_value = cls._read_text_secret(secret_path)
            if secret_value not in (None, "", "notset"):
                values[secret_name] = secret_value
        return values

    @classmethod
    def _get_companion_file_map(cls, kwargs: Dict[str, object] | None = None) -> Dict[str, str]:
        return {
            value_name: str(cls._get_effective_field_value(file_attr, kwargs))
            for value_name, file_attr in cls.COMPANION_FILE_ATTRS.items()
        }

    @classmethod
    def _load_companion_values_from_files(cls, kwargs: Dict[str, object] | None = None) -> Dict[str, str]:
        values: Dict[str, str] = {}
        for value_name, value_path in cls._get_companion_file_map(kwargs).items():
            value = cls._read_text_secret(value_path)
            if value not in (None, "", "notset"):
                values[value_name] = value
        return values

    @staticmethod
    def _derive_service_npub(service_nsec: str) -> str:
        return Keys(priv_k=service_nsec).public_key_bech32()

    @classmethod
    def _persist_generated_values_to_files(cls, values: Dict[str, str], kwargs: Dict[str, object] | None = None) -> None:
        for secret_name, secret_path in cls._get_private_secret_file_map(kwargs).items():
            if secret_name in values and values[secret_name] not in (None, "", "notset"):
                cls._write_text_secret(secret_path, values[secret_name])

        for value_name, value_path in cls._get_companion_file_map(kwargs).items():
            if value_name in values and values[value_name] not in (None, "", "notset"):
                cls._write_text_secret(value_path, values[value_name])

    @classmethod
    def _migrate_default_conf_to_secret_files(cls, default_conf_path: Path, kwargs: Dict[str, object] | None = None) -> bool:
        present_secret_files = cls._get_present_secret_files(kwargs)
        present_count = sum(1 for is_present in present_secret_files.values() if is_present)
        total_count = len(present_secret_files)

        if present_count == total_count:
            return False
        if 0 < present_count < total_count:
            missing = sorted(
                secret_name
                for secret_name, is_present in present_secret_files.items()
                if not is_present
            )
            raise RuntimeError(
                "Refusing legacy secret migration with partially populated secret files. "
                f"Missing secret files for: {', '.join(missing)}"
            )
        if not default_conf_path.exists():
            return False

        legacy_values = cls._read_conf(default_conf_path)
        migratable_secret_names = cls.PRIVATE_SECRET_FILE_ATTRS.keys()
        missing_legacy = sorted(
            secret_name
            for secret_name in migratable_secret_names
            if legacy_values.get(secret_name) in (None, "", "notset")
        )
        if missing_legacy:
            raise RuntimeError(
                "Legacy default.conf exists but is missing required private secrets for migration: "
                f"{', '.join(missing_legacy)}"
            )

        secret_file_map = cls._get_private_secret_file_map(kwargs)
        for secret_name, secret_path in secret_file_map.items():
            cls._write_text_secret(secret_path, legacy_values[secret_name])

        companion_file_map = cls._get_companion_file_map(kwargs)
        for value_name, value_path in companion_file_map.items():
            if legacy_values.get(value_name) not in (None, "", "notset"):
                cls._write_text_secret(value_path, legacy_values[value_name])

        renamed_path = default_conf_path.with_name(default_conf_path.name + ".deleteme")
        if renamed_path.exists():
            renamed_path.unlink()
        default_conf_path.rename(renamed_path)
        return True

    @staticmethod
    def _read_conf(path: Path) -> Dict[str, str]:
        values: Dict[str, str] = {}
        if not path.exists():
            return values

        for raw in path.read_text().splitlines():
            line = raw.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, value = line.split("=", 1)
            values[key.strip()] = value.strip()
        return values

    @staticmethod
    def _write_conf(path: Path, values: Dict[str, str]) -> None:
        # Stable order makes diffs cleaner
        order = [
            "SERVICE_NSEC",
            "SERVICE_NPUB",
            "NWC_NSEC",
            "PQC_SIG_SECRET_KEY",
            "PQC_SIG_PUBLIC_KEY",
            "PQC_KEM_SECRET_KEY",
            "PQC_KEM_PUBLIC_KEY",
        ]
        lines = [f"{k}={values[k]}" for k in order if k in values]
        path.write_text("\n".join(lines) + ("\n" if lines else ""))

    def __init__(self, **kwargs):
        default_conf_path = Path("data/default.conf")
        default_conf_path.parent.mkdir(parents=True, exist_ok=True)
        bootstrap_mode = bool(self._get_effective_field_value("SECRET_BOOTSTRAP_MODE", kwargs))
        if bootstrap_mode:
            self._migrate_default_conf_to_secret_files(default_conf_path, kwargs)
        legacy_migrated_conf_path = default_conf_path.with_name(default_conf_path.name + ".deleteme")

        # Load existing file values (or empty if none)
        file_values = self._read_conf(default_conf_path)
        file_values.update(self._load_private_values_from_secret_files(kwargs))
        file_values.update(self._load_companion_values_from_files(kwargs))

        if "SERVICE_NSEC" in file_values and file_values.get("SERVICE_NPUB") in (None, "", "notset"):
            file_values["SERVICE_NPUB"] = self._derive_service_npub(file_values["SERVICE_NSEC"])

        if legacy_migrated_conf_path.exists():
            legacy_values = self._read_conf(legacy_migrated_conf_path)
            for public_key_name in ("PQC_SIG_PUBLIC_KEY", "PQC_KEM_PUBLIC_KEY"):
                if file_values.get(public_key_name) in (None, "", "notset") and legacy_values.get(public_key_name) not in (None, "", "notset"):
                    file_values[public_key_name] = legacy_values[public_key_name]

        required_keys = {
            "SERVICE_NSEC",
            "SERVICE_NPUB",
            "NWC_NSEC",
            "PQC_SIG_SECRET_KEY",
            "PQC_SIG_PUBLIC_KEY",
            "PQC_KEM_PUBLIC_KEY",
            "PQC_KEM_SECRET_KEY",
        }

        # Treat "notset" as missing too (in case a stub got written previously)
        missing = {
            k
            for k in required_keys
            if (k not in os.environ) and (k not in file_values or file_values.get(k) in (None, "", "notset"))
        }

        # If anything is missing, generate *only* the missing ones and persist
        if missing:
            if not bootstrap_mode:
                raise RuntimeError(
                    "Missing required secret material and SECRET_BOOTSTRAP_MODE is disabled. "
                    f"Missing values: {', '.join(sorted(missing))}"
                )

            generated = self._gen_missing_values(missing)
            if generated:
                file_values.update(generated)
                self._persist_generated_values_to_files(generated, kwargs)

        if bootstrap_mode and default_conf_path.exists():
            legacy_snapshot = self._read_conf(default_conf_path)
            non_secret_values = {
                key: legacy_snapshot[key]
                for key in self.COMPANION_FILE_ATTRS
                if legacy_snapshot.get(key) not in (None, "", "notset")
            }
            if non_secret_values:
                self._persist_generated_values_to_files(non_secret_values, kwargs)
            renamed_path = default_conf_path.with_name(default_conf_path.name + ".deleteme")
            if renamed_path.exists():
                renamed_path.unlink()
            default_conf_path.rename(renamed_path)

        # Build fallback values: only those not already in environment
        fallback_values = {k: v for k, v in file_values.items() if k not in os.environ}

        # Merge precedence: file fallback < kwargs (explicit) ; env is handled by BaseSettings
        merged_values = {**fallback_values, **kwargs}
        super().__init__(**merged_values)

if __name__ == "__main__":
    
    print("ROOT:", ROOT)
    print(settings)
