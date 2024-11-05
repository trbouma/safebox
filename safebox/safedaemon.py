import daemon
import time
import signal
import sys
import os
import yaml 
from safebox.wallet import Wallet
from safebox.constants import (
    WELCOME_MSG

)

relays  = [ "wss://relay.nimo.cash",
            "wss://nostr-pub.wellorder.net", 
            "wss://relay.damus.io", 
            "wss://relay.primal.net",
            "wss://nos.lol"
        ]
mints   = ["https://mint.nimo.cash"]
wallet  = "default" 
home_relay = "wss://relay.openbalance.app"
replicate_relays = ["wss://relay.nimo.cash", "wss://nostr-pub.wellorder.net"]

# List of mints https://nostrapps.github.io/cashu/mints.json

home_directory = os.path.expanduser('~')
cli_directory = '.safebox'
config_file = 'config.yml'
config_directory = os.path.join(home_directory, cli_directory)
file_path = os.path.join(home_directory, cli_directory, config_file)

os.makedirs(config_directory, exist_ok=True)

if os.path.exists(file_path):
    with open(file_path, 'r') as file:
        config_obj = yaml.safe_load(file)
else:
   
    config_obj = {  'nsec': Keys().private_key_bech32(), 
                    'relays': relays, 
                    "home_relay": home_relay,
                    "mints": mints, 
                    "wallet": wallet,
                    "replicate_relays": replicate_relays}
    with open(file_path, 'w') as file:        
        yaml.dump(config_obj, file)

RELAYS  = config_obj['relays']
NSEC    = config_obj['nsec']
MINTS   = config_obj['mints']
WALLET  = config_obj['wallet']
HOME_RELAY = config_obj['home_relay']
REPLICATE_RELAYS = config_obj['replicate_relays']

def run_daemon():
    """Main function for the daemon."""
    wallet_obj = Wallet(nsec=NSEC,relays=RELAYS,mints=MINTS,home_relay=HOME_RELAY)
    nrecipient = 'npub19xlhmu806lf7yh62kmr6gg4qus9uyss4sr9jeylqqvtud36cuxls2h9s37a76-ad31-b020376b50'
    relay_array =['wss://relay.openbalance.app']
    wallet_obj.run()


def stop_daemon(signum, frame):
    """Function to handle termination signals."""
    sys.exit(0)

def main_program():
    # Set signal handlers to terminate the daemon gracefully
    signal.signal(signal.SIGTERM, stop_daemon)
    signal.signal(signal.SIGINT, stop_daemon)

    # Daemon context manager
    with daemon.DaemonContext(
        working_directory='/',
        umask=0o002,
        stdout=sys.stdout,  # Redirect stdout to syslog or a file if needed
        stderr=sys.stderr,  # Redirect stderr to syslog or a file if needed
        pidfile=None,       # You can use a PID file to track the daemon process
    ):
        run_daemon()

if __name__ == "__main__":
    main_program()

