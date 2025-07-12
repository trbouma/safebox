import pathlib

from pydantic import AnyHttpUrl, BaseModel
from pydantic_settings import BaseSettings

from typing import List, Optional, Union

import os
from pathlib import Path

from monstr.encrypt import Keys

# Project Directories
ROOT = pathlib.Path(__file__).resolve().parent.parent

class ConfigWithFallback(BaseSettings):
    SERVICE_NSEC: str


    class Config:
        case_sensitive = False

    def __init__(self, **kwargs):
        # Step 1: Ensure data/default.conf exists
        default_conf_path = Path("data/default.conf")
        default_conf_path.parent.mkdir(parents=True, exist_ok=True)

        if not default_conf_path.exists():
            k = Keys()
            default_conf_path.write_text(
                f"SERVICE_NSEC={k.private_key_bech32()}\n"
  
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



class Settings(BaseSettings):
    HOME_RELAY: str = 'wss://relay.getsafebox.app'
    HOME_MINT: str= 'https://mint.getsafebox.app'      
    SERVICE_NAME: str = 'Safebox'
    SERVICE_TAG_LINE: str = 'Your Funds. Your Records'
    SERVICE_SECRET_KEY: str|None = None
    SERVICE_RELAY_DB: str = "data/relay.db"
    TZ: str = "America/New_York"
    ALGORITHM: str = "HS256"
    DATABASE: str = "sqlite:///data/database.db"  
    RELAYS: List = ['wss://relay.getsafebox.app']
    MINTS: List = ['https://mint.getsafebox.app']
    IP_INFO_TOKEN: str = "notset"
    NFC_ECASH_CLEARING: bool = True
    LOCAL_RELAY_PORT: int = 8735
    TOKEN_EXPIRES_WEEKS: int = 4
    TOKEN_EXPIRES_HOURS: int = 8
    SESSION_AGE_DAYS: int = 30
    LOGGING_LEVEL: int = 10
    SUPPORTED_CURRENCIES: List =['CAD','USD','EUR','GBP','JPY','INR']
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
    SELECT_KINDS: List = [  
                            [340028, "ID"],
                            [34016,"Boarding Passes"],
                            [32225,"Health Records"],
                            [37375, "Personal Notes"],
                            [34002, "Credentials"],
                            [34003, "Payment Cards"],
                            [34004, "Travel Documents"],
                            [34005, "Memberships"],
                            [34006, "Gift Cards"],
                            [34007, "Coupons"],
                            [34008, "Event Tickets"],
                            [34009, "Health Passes"],
                            [34010, "Transit Cards"],
                            [34011, "Immunization Records"],
                            [34012, "Educational Diplomas"],
                            [34013, "Official Documentation"],
                            [34014, "Insurance"],
                            [34015, "Recipes"]


                        ]
    # Offer and Grant Kinds
    # Numbering Convention is the offer is odd-number and consecutive even-number is the grant
    # Can be calculated but flexible with defining both offer and grant kinds
    OFFER_KINDS: List =     [  
                            [340027, "ID"],
                            [34001, "Badges"],
                            [34029,"Passes"],
                            [32225,"Health Records"], 
                            [32229, "Prescriptions"],  
                            [32231, "Immunization Records"],    
                            [34003, "Payment Cards"],
                            [34005, "Travel Documents"],
                            [34007, "Memberships"],
                            [34009, "Gift Cards"],
                            [34011, "Coupons"],
                            [34013, "Event Tickets"],                            
                            [34017, "Transit Cards"],                            
                            [34019, "Educational Diplomas"],
                            [34021, "Official Documentation"],
                            [34023, "Insurance"],
                            [34025, "Recipes"]
                        ]  
 
    GRANT_KINDS: List =     [  
                            [34028, "ID"],
                            [34002, "Badges"],
                            [34030,"Passes"],
                            [32226,"Health Records"], 
                            [32230, "Prescriptions"],  
                            [32232, "Immunization Records"],    
                            [34004, "Payment Cards"],
                            [34006, "Travel Documents"],
                            [34008, "Memberships"],
                            [34010, "Gift Cards"],
                            [34012, "Coupons"],
                            [34014, "Event Tickets"],                            
                            [34018, "Transit Cards"],                            
                            [34020, "Educational Diplomas"],
                            [34022, "Official Documentation"],
                            [34024, "Insurance"],
                            [34026, "Recipes"]
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

if __name__ == "__main__":
    
    print("ROOT:", ROOT)
    print(settings)