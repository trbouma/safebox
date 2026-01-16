import pathlib

from pydantic import AnyHttpUrl, BaseModel
from pydantic_settings import BaseSettings

from typing import List, Optional, Union, Dict, Tuple

import os
from pathlib import Path

from monstr.encrypt import Keys
import oqs

# Project Directories
ROOT = pathlib.Path(__file__).resolve().parent.parent





class Settings(BaseSettings):
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
    RELAYS: List = ['wss://relay.getsafebox.app']
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
    INVITE_CODES: List = ["alpha", "rektuser", "earlyaccess"]
    AUTH_RELAYS: List = ['wss://relay.getsafebox.app']
    NWC_SERVICE: bool = False
    NWC_NSEC: str = 'nsec1wml8qhq2qkmemlceg2fehvg2cefqrsp7ak47rdmc3qxum65wsxaqcvj7d6'
    NWC_RELAYS: List = ['wss://relay.getsafebox.app']
    TRANSMITTAL_RELAYS: List = ['wss://relay.getsafebox.app']
    REFRESH_CURRENCY_INTERVAL: int = 3600
    TRANSMITTAL_KIND: int = 21060
    AUTH_KIND: int = 21061
    CREDENTIAL_TRANSMITTAL_KIND: int = 21062
    CREDENTIAL_TRANSMITTAL_RELAYS: List = ['wss://relay.getsafebox.app']
    RECORD_TRANSMITTAL_KIND: int = 21062
    RECORD_TRANSMITTAL_RELAYS: List = ['wss://relay.getsafebox.app']
    CURRENCY_CSV: str = 'setup/currency.csv'

    # Offer and Grant Kinds
    # Numbering Convention is the offer is odd-number and consecutive even-number is the grant
    # Can be calculated but flexible with defining both offer and grant kinds
    OFFER_KINDS: List =     [  
                            [37375, "Shared Note", ["share"]], 
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
                            [37376, "Shared Note", ["share"]], 
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
    PQC_SIG_SECRET_KEY: str = "notset"
    PQC_SIG_PUBLIC_KEY: str = "notset"
    PQC_KEM_PUBLIC_KEY: str = "notset"
    PQC_KEM_SECRET_KEY: str = "notset"

    class Config:
        case_sensitive = False

    # ---- key generation helpers ----

    @staticmethod
    def _gen_nostr_keys() -> Dict[str, str]:
        k = Keys()
        return {
            "SERVICE_NSEC": k.private_key_bech32(),
            "SERVICE_NPUB": k.public_key_bech32(),
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

        # Load existing file values (or empty if none)
        file_values = self._read_conf(default_conf_path)

        required_keys = {
            "SERVICE_NSEC",
            "SERVICE_NPUB",
            "PQC_SIG_SECRET_KEY",
            "PQC_SIG_PUBLIC_KEY",
            "PQC_KEM_PUBLIC_KEY",
            "PQC_KEM_SECRET_KEY",
        }

        # Treat "notset" as missing too (in case a stub got written previously)
        missing = {k for k in required_keys if k not in file_values or file_values.get(k) in (None, "", "notset")}

        # If anything is missing, generate *only* the missing ones and persist
        if missing:
            generated = self._gen_missing_values(missing)
            if generated:
                file_values.update(generated)
                self._write_conf(default_conf_path, file_values)

        # Build fallback values: only those not already in environment
        fallback_values = {k: v for k, v in file_values.items() if k not in os.environ}

        # Merge precedence: file fallback < kwargs (explicit) ; env is handled by BaseSettings
        merged_values = {**fallback_values, **kwargs}
        super().__init__(**merged_values)

if __name__ == "__main__":
    
    print("ROOT:", ROOT)
    print(settings)