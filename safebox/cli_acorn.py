import asyncio, sys, click, os, yaml
from typing import List
from monstr.encrypt import Keys
from monstr.client.client import Client, ClientPool
from monstr.event.event import Event
from safebox.acorn import Acorn
from safebox.models import nostrProfile, SafeboxItem
from datetime import datetime

from safebox.lightning import lightning_address_pay
from time import sleep, time
import qrcode
from safebox.func_utils import recover_nsec_from_seed
from safebox.prompts import (
    WELCOME_MSG,
    INFO_HELP,
    SET_HELP,
    NSEC_HELP,
    RELAYS_HELP,
    HOME_RELAY_HELP,
    MINTS_HELP,
    NOSTR_PROFILE_HELP

)

relays  = [ "wss://nostr-pub.wellorder.net", 
            "wss://relay.damus.io", 
            "wss://relay.primal.net",
            "wss://nos.lol"
        ]
mints   = ["https://mint.nimo.cash"]
wallet  = "default" 
home_relay = "wss://relay.openbalance.app"
replicate_relays = ["wss://nostr-pub.wellorder.net"]
logging_level = 20

# List of mints https://nostrapps.github.io/cashu/mints.json

home_directory = os.path.expanduser('~')
cli_directory = '.acorn'
config_file = 'config.yml'
config_directory = os.path.join(home_directory, cli_directory)
file_path = os.path.join(home_directory, cli_directory, config_file)
def write_config():
     with open(file_path, 'w') as file:        
        yaml.dump(config_obj, file)

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
                    "replicate_relays": replicate_relays,
                    "logging_level": 10}
    with open(file_path, 'w') as file:        
        yaml.dump(config_obj, file)

RELAYS  = config_obj.get('relays',relays)
NSEC    = config_obj.get('nsec',None)
MINTS   = config_obj.get('mints', mints)
WALLET  = config_obj.get('wallet', wallet)
HOME_RELAY = config_obj.get('home_relay', home_relay)
REPLICATE_RELAYS = config_obj.get('replicate_relays', replicate_relays)
LOGGING_LEVEL = config_obj.get('logging_level',10)

if NSEC == None:
    click.echo("Private key is not set")
    if click.confirm("Do you want to generate a new key?"):
        
        write_config()

    sys.exit()

write_config()



@click.group()
def cli():
    pass

@click.command("info", help=INFO_HELP)
@click.pass_context
def info(ctx):
    
    click.echo(WELCOME_MSG)
    click.echo("This is acorn. Retrieving wallet...")
    acorn_obj = Acorn(nsec=NSEC, home_relay=HOME_RELAY, logging_level=LOGGING_LEVEL)
   
    click.echo(f"npub: {acorn_obj.pubkey_bech32}")
    # click.echo(f"instance: {acorn_obj.get_instance()}")
    click.echo(f"tags: {acorn_obj.acorn_tags}")
    acorn_obj.update_tags([["balance","26"]])

@click.command(help="initialize a new safebox")

@click.option("--homerelay","-h", is_flag=True, show_default=True, default=False, help=HOME_RELAY_HELP)
@click.option("--keepkey","-k", is_flag=True, show_default=True, default=False, help="Keep existing key(nsec).")
@click.option("--longseed","-l", is_flag=True, show_default=True, default=False, help="Generate long seed of 24 words")
@click.option('--name', '-n', default="wallet", help=HOME_RELAY_HELP)
def init(keepkey, longseed, homerelay,name):
    click.echo(f"Creating a new acorn with relay: {HOME_RELAY} and mint: {MINTS}")
    
    acorn_obj = Acorn(nsec=NSEC, relays=RELAYS, mints=MINTS, home_relay=HOME_RELAY, logging_level=LOGGING_LEVEL)

    if keepkey:
        click.echo("Keep existing key")
    config_obj['nsec'] = acorn_obj.create_instance(keepkey,longseed, name)
    
    # click.echo(acorn_obj.get_profile())
    write_config()
    # click.echo(acorn_obj.get_post())
    


@click.command("set", help="set local config options")
@click.option('--nsec', '-n', default=None, help=NSEC_HELP)
@click.option('--relays', '-r', default=None, help=RELAYS_HELP)
@click.option('--home', '-h', default=None, help=HOME_RELAY_HELP)
@click.option('--mints', '-m', default=None, help=MINTS_HELP)
@click.option('--xrelays', '-x', default=None, help='set replicate relays')
@click.option('--logging', '-l', default=None, help='set logging level')
def set(nsec, home, relays, mints,xrelays, logging: int):
    
    if nsec == None and relays == None and mints == None and home == None and xrelays==None and logging == None:
        click.echo(yaml.dump(config_obj, default_flow_style=False))
        return
   

    if nsec != None:
        config_obj['nsec']=nsec

    if logging != None:
        config_obj['logging_level']= int(logging)

    
    if home != None:
        if "wss://" in home:
            home_relay = home
        elif "ws://" in home:
            home_relay = home
        else:
            home_relay = f"wss://{home}"


        print("home relay", home_relay)
        config_obj['home_relay']=home_relay
    
    if relays != None:
        print("relays:", relays)
        relay_array = str(relays).replace(" ","").split(',')
        relay_array_wss = []
        for each in relay_array:
            relay_array_wss.append(each if "wss://" in each else "wss://"+each)
        print(relay_array_wss)
        config_obj['relays']=relay_array_wss
    else:
       config_obj['relays']=RELAYS 

    if xrelays != None:
        print("replicate relays:", xrelays)
        relay_array = str(xrelays).replace(" ","").split(',')
        relay_array_wss = []
        for each in relay_array:
            relay_array_wss.append(each if "wss://" in each else "wss://"+each)
        print(relay_array_wss)
        config_obj['replicate_relays']=relay_array_wss
    else:
       config_obj['replicate_relays']=REPLICATE_RELAYS 

    if mints != None:
        
        mint_array = str(mints).replace(" ","").split(',') 
        mint_array_https = []
        for each in mint_array:
            mint_array_https.append(each if "https://" in each else "https://"+each)

        config_obj['mints']=mint_array_https
        print("setting mints" , mint_array_https)
       
    else:
       config_obj['mints']=MINTS 



    acorn_obj = Acorn(nsec=NSEC, relays=RELAYS, mints=MINTS, home_relay=HOME_RELAY, logging_level=LOGGING_LEVEL)
    click.echo("set!")

    # print(config_obj)
    click.echo(yaml.dump(config_obj,default_flow_style=False))
    with open(file_path, 'w') as file:        
        yaml.dump(config_obj, file)

@click.command("balance", help="get balance")
def get_balance():
    
    acorn_obj = Acorn(nsec=NSEC, relays=RELAYS, home_relay=HOME_RELAY, logging_level=LOGGING_LEVEL)

    click.echo(f"{acorn_obj.balance} sats in {len(acorn_obj.proofs)} proofs.")

@click.command("profile", help="get profile")
@click.option('--name', '-n', default="wallet", help=HOME_RELAY_HELP)
def get_profile(name):
    
    acorn_obj = Acorn(nsec=NSEC, relays=RELAYS, home_relay=HOME_RELAY, logging_level=LOGGING_LEVEL)
    click.echo(acorn_obj.get_profile(name))

cli.add_command(info)
cli.add_command(init)
cli.add_command(set)
cli.add_command(get_balance)
cli.add_command(get_profile)


if __name__ == "__main__":
   cli()