import pathlib

from pydantic import AnyHttpUrl, BaseModel
from pydantic_settings import BaseSettings

from typing import List, Optional, Union

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
                            [34042, "Skilled Trade"],                        
                            [37375, "Personal Note", ["share"]] 
                            
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
    PQC_SECRET_KEY: str = "notset"
    
    

    class Config:
        case_sensitive = False

    def __init__(self, **kwargs):
        # Step 1: Ensure data/default.conf exists
        default_conf_path = Path("data/default.conf")
        default_conf_path.parent.mkdir(parents=True, exist_ok=True)

        if not default_conf_path.exists():
            k = Keys()  
            signer = oqs.Signature(settings.PQC_SIGALG)
            signer_public_key = signer.generate_keypair()    
            pq_pubkey = signer_public_key.hex()
            secret_key = signer.export_secret_key()
    
            default_conf_path.write_text(
                f"SERVICE_NSEC={k.private_key_bech32()}\nPQC_SECRET_KEY={secret_key.hex()}"
  
            )

        # Step 2: Load values from default.conf if not in os.environ
        fallback_values = {}
        with open(default_conf_path) as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                if "=" in line:
                    key, value = line.split("=", 1)
                    key = key.strip()
                    value = value.strip()
                    if key not in os.environ:
                        fallback_values[key] = value

        # Step 3: Merge fallback_values with any passed-in kwargs
        merged_values = {**fallback_values, **kwargs}

        # Step 4: Call super().__init__ with merged values
        super().__init__(**merged_values)

if __name__ == "__main__":
    
    print("ROOT:", ROOT)
    print(settings)