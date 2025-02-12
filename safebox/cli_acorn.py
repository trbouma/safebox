import asyncio, sys, click, os, yaml
from typing import List
from monstr.encrypt import Keys
from monstr.client.client import Client, ClientPool
from monstr.event.event import Event
from monstr.util import util_funcs
from safebox.acorn import Acorn
from safebox.models import nostrProfile, SafeboxItem
from datetime import datetime, timedelta

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
home_relay = "wss://relay.getsafebox.app"
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
    
    

@click.command(help="initialize a new safebox")

@click.option("--homerelay","-h", is_flag=True, show_default=True, default=False, help=HOME_RELAY_HELP)
@click.option("--keepkey","-k", is_flag=True, show_default=True, default=False, help="Keep existing key(nsec).")
@click.option("--longseed","-l", is_flag=True, show_default=True, default=False, help="Generate long seed of 24 words")
@click.option('--name', '-n', default="wallet", help=HOME_RELAY_HELP)
def init(keepkey, longseed, homerelay,name):
    click.echo(f"Creating a new acorn with relay: {HOME_RELAY} and mint: {MINTS}")
    
    acorn_obj = Acorn(nsec=NSEC, relays=RELAYS, mints=MINTS, home_relay=HOME_RELAY, logging_level=LOGGING_LEVEL)
    asyncio.run(acorn_obj.load_data())

    if keepkey:
        click.echo("Keep existing key")
    click.echo("Create new instance")
    config_obj['nsec'] = asyncio.run(acorn_obj.create_instance(keepkey,longseed, name))
    
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
    asyncio.run(acorn_obj.load_data())
    click.echo(acorn_obj.get_profile(name))

@click.command("setowner", help="get profile")
@click.option('--owner', '-o', default=None, help="set owner npub")
@click.option('--currency', '-c', default=None, help="set local currency")
def set_owner(owner, currency):
    
    acorn_obj = Acorn(nsec=NSEC, relays=RELAYS, home_relay=HOME_RELAY, logging_level=LOGGING_LEVEL)
    asyncio.run(acorn_obj.load_data())
    msg_out = asyncio.run(acorn_obj.set_owner_data(npub=owner,local_currency=currency))
    click.echo(msg_out)
    

@click.command("deposit", help="deposit funds into wallet via lightning invoice")
@click.argument('amount')
@click.option('--mint', '-m', default=None, help="deposit mint")
def deposit(amount: int, mint:str):
    if mint:
        mint = mint.replace("https://", "")
    qr = qrcode.QRCode()
    click.echo(f"amount: {amount} mint:{mint}")
    acorn_obj = Acorn(nsec=NSEC, relays=RELAYS,home_relay=HOME_RELAY, mints=MINTS, logging_level=LOGGING_LEVEL)
    asyncio.run(acorn_obj.load_data())
    cli_quote = acorn_obj.deposit(amount, mint)
    qr.add_data(cli_quote.invoice)
    qr.make(fit=True)
    click.echo(f"\n\nQuote:\n{cli_quote.quote}\n") 
    click.echo(f"\n\nPlease pay invoice:\n{cli_quote.invoice}\n") 
    qr_invoice = qr.print_ascii(out=sys.stdout)
    click.echo(f"\n{qr_invoice}\n") 
    
    if click.confirm("Press any key to continue..."):
        start_time = time()  # Record the start time
        end_time = start_time + 60  # Set the loop to run for 60 seconds

        while time() < end_time:
            
            print("checking")
            success = asyncio.run(acorn_obj.check_quote(cli_quote.quote, amount, mint))
            if success:
                break
            sleep(3)  # Sleep for 3 seconds

        click.echo("Loop completed.")

    click.echo("Done!")
 
@click.command("proofs", help="list proofs") 
def proofs():
    
    acorn_obj = Acorn(nsec=NSEC, relays=RELAYS, home_relay=HOME_RELAY, logging_level=LOGGING_LEVEL)
    asyncio.run(acorn_obj.load_data())
    click.echo(f"{acorn_obj.balance} sats in {len(acorn_obj.proofs)} proofs in {acorn_obj.events} events")
    for each in acorn_obj.proofs:
        click.echo(f"id: {each.id} amount: {each.amount} Y: {each.Y}")
    click.echo(f"{acorn_obj.powers_of_2_sum(acorn_obj.balance)}")
    click.echo("Proofs by keyset")
    all_proofs, keyset_amounts = acorn_obj._proofs_by_keyset()
    click.echo(f"{keyset_amounts}")
    click.echo(f"Known mints: {acorn_obj.known_mints}")

@click.command("swap", help="swap proofs for new proofs")
@click.option("--consolidate","-c", is_flag=True, show_default=True, default=False, help="Consolidate proofs")
def swap(consolidate):
    
    acorn_obj = Acorn(nsec=NSEC, relays=RELAYS, mints=MINTS, home_relay=HOME_RELAY, logging_level=LOGGING_LEVEL)
    asyncio.run(acorn_obj.load_data())
    # msg_out = wallet_obj.get_proofs()
    # wallet_obj.delete_proofs()
    # click.echo(msg_out)
    
    if consolidate:
        click.echo("Consolidate proofs")
        result_out = asyncio.run(acorn_obj.swap_multi_consolidate())
        click.echo(result_out)
    else:
        click.echo("Swap proofs")
        result_out = asyncio.run(acorn_obj.swap_multi_each())
        click.echo(result_out)

@click.command("pay", help="Payout funds to lightning address")
@click.argument('amount', default=21)
@click.argument('lnaddress', default='trbouma@openbalance.app')
@click.option('--comment','-c', default='Paid!')
def pay(amount,lnaddress: str, comment:str):
    click.echo(f"Pay to: {lnaddress}")
    acorn_obj = Acorn(nsec=NSEC, home_relay=HOME_RELAY, relays=RELAYS,mints=MINTS, logging_level=LOGGING_LEVEL)
    asyncio.run(acorn_obj.load_data())
    try:
        msg_out = asyncio.run(acorn_obj.pay_multi(amount,lnaddress,comment))
        click.echo(msg_out)
    except Exception as e:
        click.echo(f"Error: {e}")

@click.command("put", help='write a private record')
@click.argument('label', default='default')
@click.argument('label_info', default='hello')
@click.option('--kind','-k', default=37375)
def put(label, label_info, kind):
    jsons=None
    acorn_obj = Acorn(nsec=NSEC, relays=RELAYS, home_relay=HOME_RELAY, logging_level=LOGGING_LEVEL)
    asyncio.run(acorn_obj.load_data())
    # click.echo(wallet.get_wallet_info())
    

    if click.confirm('Do you want to continue?'):    
     asyncio.run(acorn_obj.put_record(label, label_info,record_kind=kind))

@click.command("get", help='get a private wallet record')
@click.argument('label', default = "default")
@click.option('--kind','-k', default=37375)
def get(label,kind):
    
    out_info = "None"
    acorn_obj = Acorn(nsec=NSEC, relays=RELAYS, home_relay=HOME_RELAY, mints= MINTS, logging_level=LOGGING_LEVEL)
    asyncio.run(acorn_obj.load_data())

    try:
        out_info = asyncio.run(acorn_obj.get_wallet_info(label,record_kind=kind))
        # safebox_info = wallet_obj.get_record(label)
        pass

    except:
        out_info = "No label found!"
    
    click.echo(out_info)

@click.command("delete", help='get a private wallet record')
@click.argument('label', default = "default")
def delete_record(label):
    
    out_info = "None"
    acorn_obj = Acorn(nsec=NSEC, relays=RELAYS, home_relay=HOME_RELAY, mints= MINTS, logging_level=LOGGING_LEVEL)
    asyncio.run(acorn_obj.load_data())

    try:
        out_info = asyncio.run(acorn_obj.delete_wallet_info(label))
        # safebox_info = wallet_obj.get_record(label)
        pass

    except:
        out_info = "No label found!"
    
    click.echo(out_info)

@click.command("deletekind", help='delete kind records')
@click.option('--kind','-k', default=30000)
def delete_kind(kind):
    
    if not click.confirm("Are you really sure? This is a dangerous option"):
        return
    
    out_info = "None"
    acorn_obj = Acorn(nsec=NSEC, relays=RELAYS, home_relay=HOME_RELAY, mints= MINTS, logging_level=LOGGING_LEVEL)
    asyncio.run(acorn_obj.load_data())

    try:
        out_info = asyncio.run(acorn_obj.delete_kind_events(kind))
        
        pass

    except:
        out_info = "No label found!"
    
    click.echo(out_info)

@click.command("getrecords", help='get a private wallet record')
@click.option('--kind','-k', default=37375)
@click.option('--since','-s', default=None, help='since in hours')
def get_records(kind, since):
    
    out_info = "None"
    acorn_obj = Acorn(nsec=NSEC, relays=RELAYS, home_relay=HOME_RELAY, mints= MINTS, logging_level=LOGGING_LEVEL)
    asyncio.run(acorn_obj.load_data())

    if since != None:
        since_adjusted = util_funcs.date_as_ticks((datetime.now()-timedelta(hours=int(since))))
        click.echo(since_adjusted)
    else:
        since_adjusted = None

    try:
        out_info = asyncio.run(acorn_obj.get_user_records(record_kind=kind, since=since_adjusted))
        
        for each in out_info:
            click.echo(f"RECORD: {each}")
        click.echo(f"No. of RECORDS: {len(out_info)}" )

    except:
        click.echo("No label found!")
    


@click.command("balance", help="show balance")
def balance():
    
    acorn_obj = Acorn(nsec=NSEC, relays=RELAYS, home_relay=HOME_RELAY, mints=MINTS, logging_level=LOGGING_LEVEL)
    asyncio.run(acorn_obj.load_data())

    click.echo(f"{acorn_obj.balance} sats in {len(acorn_obj.proofs)} proofs.")

@click.command("zap", help="Zap amount to event or to recipient")
@click.argument('amount', default=1)
@click.argument('event')
@click.option('--comment','-c', default='⚡️')
def zap(amount:int, event, comment):

    if event == None:
        click.echo("Need an event!")
        return
    
    acorn_obj = Acorn(nsec=NSEC, home_relay=HOME_RELAY, relays=RELAYS,logging_level=LOGGING_LEVEL)
    asyncio.run(acorn_obj.load_data())
    # click.echo(f"Zap amount: {amount} to {event}")
   
    result_out = asyncio.run(acorn_obj.zap(amount,event,comment))    
    click.echo(result_out)

@click.command(help="Accept cashu token")
@click.argument('token')
def accept(token):
    
    acorn_obj = Acorn(nsec=NSEC, relays=RELAYS, home_relay=HOME_RELAY, logging_level=LOGGING_LEVEL)
    asyncio.run(acorn_obj.load_data())
    # msg_out = wallet_obj.get_proofs()
    # wallet_obj.delete_proofs()
    # click.echo(msg_out)
    result_out = asyncio.run(acorn_obj.accept_token(token))
    click.echo(result_out)

@click.command("issue", help="Issue token amount")
@click.argument('amount', default=1)
def issue(amount:int):
    click.echo(f"Issue token amount: {amount}")
    acorn_obj = Acorn(nsec=NSEC, relays=RELAYS,mints=MINTS,home_relay=HOME_RELAY, logging_level=LOGGING_LEVEL)
    asyncio.run(acorn_obj.load_data())
    token = asyncio.run(acorn_obj.issue_token(amount))
    click.echo(token)

@click.command("send", help="Send amount to nip05 address or npub")
@click.argument('amount', default=21)
@click.argument('nrecipient', default=None)
@click.option('--comment','-c', default='Paid!')
@click.option('--relays','-r', default=HOME_RELAY)
def send(amount,nrecipient: str, relays:str, comment:str):
    ecash_relays = []

   
    for each in relays.split(","):
        each = "wss://" + each if not each.startswith("wss://") else each
        ecash_relays.append(each)
    
    click.echo(f"Send to: {amount} to {nrecipient} via {ecash_relays}")
    acorn_obj = Acorn(nsec=NSEC, home_relay=HOME_RELAY, relays=RELAYS,mints=MINTS)
    out_msg = acorn_obj.send_ecash_dm(amount=amount,nrecipient=nrecipient,ecash_relays=ecash_relays, comment=comment)
    click.echo(out_msg)

@click.command("dm", help="Send message to nip05 address or npub")
@click.argument('nrecipient', default=None)
@click.argument('message', default="hello")
@click.option('--relays','-r', default=HOME_RELAY)
def dm_recipient(nrecipient: str, message: str, relays:str):
    dm_relays = []

   
    for each in relays.split(","):
        each = "wss://" + each if not each.startswith("wss://") else each
        dm_relays.append(each)
    
    click.echo(f"Send: {message} to {nrecipient} via {dm_relays}")
    acorn_obj = Acorn(nsec=NSEC, home_relay=HOME_RELAY, relays=RELAYS,mints=MINTS)
    asyncio.run(acorn_obj.load_data())
    msg_out = asyncio.run(acorn_obj.secure_dm(nrecipient=nrecipient,message=message,dm_relays=dm_relays))
    click.echo(msg_out)

@click.command("run", help='run as a service')
@click.option('--relays','-r', default=HOME_RELAY)
def run(relays):
    # click.echo(WELCOME_MSG)
    # click.echo(f"Running as a service...")
    relay_array = []
    relays_str = relays.split(',')
    for each in relays_str:
        each = "wss://" + each if not each.startswith("wss://") else each
        relay_array.append(each)
    acorn_obj = Acorn(nsec=NSEC,relays=RELAYS,mints=MINTS,home_relay=HOME_RELAY)
    asyncio.run(acorn_obj.load_data())    
    acorn_obj.run(relay_array)

@click.command("recover", help='Recover a wallet from seed phrase')
@click.argument('seedphrase', default=None)
@click.option('--homerelay','-h', default=HOME_RELAY)
def recover(seedphrase, homerelay):
    nsec = recover_nsec_from_seed(seed_phrase=seedphrase)
   
    homerelay = "wss://" + homerelay if not homerelay.startswith("wss://") else homerelay
    
    if click.confirm(f"Do you want to recover to this wallet using {homerelay}?"):
        click.echo(f"Recover seed phrase {nsec}")
        NSEC=nsec
        config_obj['home_relay']=homerelay
        config_obj['nsec']=nsec
        write_config()
        wallet_obj = Acorn(nsec=nsec, relays=RELAYS, home_relay=homerelay, logging_level=LOGGING_LEVEL)

cli.add_command(info)
cli.add_command(init)
cli.add_command(set)
cli.add_command(get_balance)
cli.add_command(get_profile)
cli.add_command(deposit)
cli.add_command(proofs)
cli.add_command(swap)
cli.add_command(pay)
cli.add_command(put)
cli.add_command(get)
cli.add_command(delete_record)
cli.add_command(delete_kind)
cli.add_command(get_records)
cli.add_command(balance)
cli.add_command(zap)
cli.add_command(accept)
cli.add_command(issue)
cli.add_command(send)
cli.add_command(recover)
cli.add_command(set_owner)
cli.add_command(dm_recipient)
cli.add_command(run)


if __name__ == "__main__":
   cli()