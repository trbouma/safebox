import asyncio, sys, click, os, yaml
from typing import List
from monstr.encrypt import Keys
from monstr.client.client import Client, ClientPool
from monstr.event.event import Event
from safebox.wallet import Wallet
from safebox.models import nostrProfile, SafeboxItem
from datetime import datetime
from safebox.wallet import Wallet
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
mints   = ["https://mint.coinos.io"]
wallet  = "default" 
home_relay = "wss://relay.openbalance.app"
replicate_relays = ["wss://nostr-pub.wellorder.net"]
logging_level = 20

# List of mints https://nostrapps.github.io/cashu/mints.json

home_directory = os.path.expanduser('~')
cli_directory = '.safebox'
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

@click.command(help=INFO_HELP)
@click.pass_context
def info(ctx):
    
    click.echo(WELCOME_MSG)
    click.echo("This is safebox. Retrieving wallet...")
    info_out = Wallet(nsec=NSEC, home_relay=HOME_RELAY, logging_level=LOGGING_LEVEL)
   
    click.echo(f"npub: {info_out.pubkey_bech32}")

@click.command(help="initialize a new safebox")
@click.option("--profile","-p", is_flag=True, show_default=True, default=False, help=NOSTR_PROFILE_HELP)
@click.option("--homerelay","-h", is_flag=True, show_default=True, default=False, help=HOME_RELAY_HELP)
@click.option("--keepkey","-k", is_flag=True, show_default=True, default=False, help="Keep existing key(nsec).")
@click.option("--longseed","-l", is_flag=True, show_default=True, default=False, help="Generate long seed of 24 words")
def init(profile, keepkey, longseed, homerelay):
    click.echo(f"Creating a new safebox with relay: {HOME_RELAY} and mint: {MINTS}")
    
    wallet_obj = Wallet(nsec=NSEC, relays=RELAYS, mints=MINTS, home_relay=HOME_RELAY, logging_level=LOGGING_LEVEL)
    if profile:
        click.echo("Create nostr profile")
    if keepkey:
        click.echo("Keep existing key")
    config_obj['nsec'] = wallet_obj.create_profile(profile,keepkey,longseed)
    
    click.echo(wallet_obj.get_profile())
    write_config()
    click.echo(wallet_obj.get_post())
    


@click.command(help="set local config options")
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



    wallet_obj = Wallet(nsec=NSEC, relays=RELAYS, mints=MINTS, home_relay=HOME_RELAY, logging_level=LOGGING_LEVEL)
    click.echo("set!")

    # print(config_obj)
    click.echo(yaml.dump(config_obj,default_flow_style=False))
    with open(file_path, 'w') as file:        
        yaml.dump(config_obj, file)


@click.command(help='display nostr profile')
@click.option('--homerelay', '-h', default=None, help='set home relay')
def profile(homerelay):
    if not homerelay:
        homerelay=HOME_RELAY    
    else:
        homerelay = "wss://" + homerelay if not homerelay.startswith("wss://") else homerelay

    click.echo(f"home relay to use: {homerelay}")
    try: 
        wallet = Wallet(nsec=NSEC,home_relay=homerelay, logging_level=LOGGING_LEVEL)       
        click.echo(wallet.get_profile())
        click.echo(wallet.get_post())
    except Exception as e:
        click.echo(f"Error {e}")


@click.command(help='replicate safebox data to other relays')
def replicate():
    wallet = Wallet(nsec=NSEC,relays=RELAYS, home_relay=HOME_RELAY)
    print("REPLICATE RELAYS:", REPLICATE_RELAYS)
    click.echo(wallet.replicate_safebox(REPLICATE_RELAYS))
    # click.echo(replicate)
    
       



@click.command(help='get a private wallet record')
@click.argument('label', default = "default")
def get(label):
    
    safebox_info = "None"
    wallet_obj = Wallet(nsec=NSEC, relays=RELAYS, home_relay=HOME_RELAY, logging_level=LOGGING_LEVEL)

    try:
        safebox_info = wallet_obj.get_wallet_info(label)
        # safebox_info = wallet_obj.get_record(label)
        pass

    except:
        safebox_info = "No label found!"
    
    click.echo(safebox_info)

@click.command(help='Recover a wallet from seed phrase')
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
        wallet_obj = Wallet(nsec=nsec, relays=RELAYS, home_relay=homerelay, logging_level=LOGGING_LEVEL)


@click.command(help='help for put')
@click.argument('label', default='default')
@click.argument('label_info', default='hello')

def put(label, label_info):
    jsons=None
    wallet_obj = Wallet(nsec=NSEC, relays=RELAYS, home_relay=HOME_RELAY, logging_level=LOGGING_LEVEL)
    # click.echo(wallet.get_wallet_info())
    

    if click.confirm('Do you want to continue?'):    
     wallet_obj.put_record(label, label_info)

@click.command(help='Do a post')
@click.argument('message', default="Hello, World!")

def post(message):
    click.echo(message)
    wallet_obj = Wallet(nsec=NSEC, relays=RELAYS, home_relay=HOME_RELAY)
    wallet_obj.send_post(message)

@click.command(help='Do a secure DM (NIP-17)')
@click.argument('nrecipient', default=None)
@click.argument('message', default="Hello,")
@click.option('--relays','-r', default=HOME_RELAY)

def dm(nrecipient,message, relays):
    dm_relays = []   
    for each in relays.split(","):
        each = "wss://" + each if not each.startswith("wss://") else each
        dm_relays.append(each)

    click.echo(f"Send to {nrecipient}: {message} via {dm_relays}")
    wallet_obj = Wallet(nsec=NSEC, relays=RELAYS, home_relay=HOME_RELAY)
    wallet_obj.secure_dm(nrecipient=nrecipient,message=message, dm_relays=dm_relays)





@click.command(help="deposit funds into wallet via lightning invoice")
@click.argument('amount')
def deposit(amount: int):
    qr = qrcode.QRCode()
    click.echo(f"amount: {amount}")
    wallet_obj = Wallet(nsec=NSEC, relays=RELAYS,mints=MINTS,home_relay=HOME_RELAY, logging_level=LOGGING_LEVEL)
    cli_quote = wallet_obj.deposit(amount)
    qr.add_data(cli_quote.invoice)
    qr.make(fit=True)
    click.echo(f"\n\nPlease pay invoice:\n{cli_quote.invoice}\n") 
    qr_invoice = qr.print_ascii(out=sys.stdout)
    click.echo(f"\n{qr_invoice}\n") 
    

    click.echo(f"\n\nPlease run safebox check invoice check to see if invoice is paid")

@click.command(help="withdraw funds from wallet via lightning invoice")
@click.argument('invoice')

def withdraw(invoice: str):
    click.echo(f"invoice: {invoice}")
    wallet_obj = Wallet(nsec=NSEC, relays=RELAYS,mints=MINTS,home_relay=HOME_RELAY)
    cli_out = wallet_obj.withdraw(invoice)
    click.echo(cli_out) 

 
    
@click.command(help="Check for payment")
@click.argument('param')

def check(param):
    wallet_obj = Wallet(nsec=NSEC, home_relay=HOME_RELAY, logging_level=LOGGING_LEVEL)
    if param == "invoice":
        click.echo("check invoice")        
        msg_out = wallet_obj.check()
        click.echo(f"Invoices paid: {msg_out}. Wallet balance is: {wallet_obj.balance} sats")
    elif param == "ecash":
        click.echo("check for ecash")
        msg_out = wallet_obj.get_ecash_dm()
        
        click.echo(msg_out)

@click.command(help="Payout funds to lightning address")
@click.argument('amount', default=21)
@click.argument('lnaddress', default='trbouma@openbalance.app')
@click.option('--comment','-c', default='Paid!')
def pay(amount,lnaddress: str, comment:str):
    click.echo(f"Pay to: {lnaddress}")
    wallet_obj = Wallet(nsec=NSEC, home_relay=HOME_RELAY, relays=RELAYS,mints=MINTS, logging_level=LOGGING_LEVEL)
    msg_out = wallet_obj.pay_multi(amount,lnaddress,comment)
    click.echo(msg_out)



@click.command(help="Send amount to nip05 address or npub")
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
    wallet_obj = Wallet(nsec=NSEC, home_relay=HOME_RELAY, relays=RELAYS,mints=MINTS)
    out_msg = wallet_obj.send_ecash_dm(amount=amount,nrecipient=nrecipient,ecash_relays=ecash_relays, comment=comment)
    click.echo(out_msg)
    #wallet_obj.pay_multi(amount,lnaddress,comment)
    # wallet_obj.swap_multi_consolidate()


@click.command(help="Share record to nip05 address or npub")
@click.argument('record')
@click.argument('nrecipient', default=None)
@click.option('--comment','-c', default='Shared!')
@click.option('--relays','-r', default='relay.openbalance.app')
def share (record,nrecipient: str, relays:str, comment:str):
    share_relays = []

   
    for each in relays.split(","):
     share_relays.append("wss://"+each)
    
    if click.confirm(f"Do you want to share {record} record to {nrecipient} via {share_relays}?"):    
        wallet_obj = Wallet(nsec=NSEC, home_relay=HOME_RELAY, relays=RELAYS,mints=MINTS)
        out_msg = wallet_obj.share_record(record=record, nrecipient=nrecipient,share_relays=share_relays, comment=comment)
        click.echo(out_msg)
 
@click.command(help="Test pay amount")
@click.argument('amount', default=21)

def testpay(amount):
    
    wallet_obj = Wallet(nsec=NSEC, home_relay=HOME_RELAY, relays=RELAYS,mints=MINTS)
    click.echo(wallet_obj.testpay(amount=amount))
    

@click.command(help="Issue token amount")
@click.argument('amount', default=1)
def issue(amount:int):
    click.echo(f"Issue token amount: {amount}")
    wallet_obj = Wallet(nsec=NSEC, relays=RELAYS,mints=MINTS,home_relay=HOME_RELAY, logging_level=LOGGING_LEVEL)
    token = wallet_obj.issue_token(amount)
    click.echo(token)

@click.command(help="Zap amount to event or to recipient")
@click.argument('amount', default=1)
@click.argument('event')
@click.option('--comment','-c', default='⚡️')

def zap(amount:int, event, comment):

    if event == None:
        click.echo("Need an event!")
        return
    
    wallet_obj = Wallet(nsec=NSEC, home_relay=HOME_RELAY, logging_level=LOGGING_LEVEL)
    # click.echo(f"Zap amount: {amount} to {event}")
   
        
    click.echo(wallet_obj.zap(amount,event,comment))
    
    
    
    

@click.command(help='Delete proofs')
def delete():
    if click.confirm("Are you really sure?"):
        click.echo("Deleting proofs...")
        wallet_obj = Wallet(nsec=NSEC, relays=RELAYS, mints=MINTS, home_relay=HOME_RELAY)
        wallet_obj.delete_proofs()
    

@click.command(help="list proofs")
def proofs():
    
    wallet_obj = Wallet(nsec=NSEC, relays=RELAYS, home_relay=HOME_RELAY, logging_level=LOGGING_LEVEL)
    # msg_out = wallet_obj.get_proofs()
    # wallet_obj.delete_proofs()
    # click.echo(msg_out)
    click.echo(f"{wallet_obj.balance} sats in {len(wallet_obj.proofs)} proofs in {wallet_obj.events} events")
    for each in wallet_obj.proofs:
        click.echo(f"id: {each.id} amount: {each.amount} Y: {each.Y}")
    click.echo(f"{wallet_obj.powers_of_2_sum(wallet_obj.balance)}")
    click.echo("Proofs by keyset")
    all_proofs, keyset_amounts = wallet_obj._proofs_by_keyset()
    click.echo(f"{keyset_amounts}")



@click.command(help="show balance")
def balance():
    
    wallet_obj = Wallet(nsec=NSEC, relays=RELAYS, home_relay=HOME_RELAY, logging_level=LOGGING_LEVEL)

    click.echo(f"{wallet_obj.balance} sats in {len(wallet_obj.proofs)} proofs.")


@click.command(help="swap proofs for new proofs")
@click.option("--consolidate","-c", is_flag=True, show_default=True, default=False, help="Consolidate proofs")
def swap(consolidate):
    
    wallet_obj = Wallet(nsec=NSEC, relays=RELAYS, mints=MINTS, home_relay=HOME_RELAY, logging_level=LOGGING_LEVEL)
    # msg_out = wallet_obj.get_proofs()
    # wallet_obj.delete_proofs()
    # click.echo(msg_out)
    
    if consolidate:
        click.echo("Consolidate proofs")
        click.echo(wallet_obj.swap_multi_consolidate())
    else:
        click.echo(wallet_obj.swap_multi_each())

@click.command(help="Receive cashu token")
@click.argument('token')
def receive(token):
    
    wallet_obj = Wallet(NSEC, RELAYS, MINTS)
    # msg_out = wallet_obj.get_proofs()
    # wallet_obj.delete_proofs()
    # click.echo(msg_out)
    click.echo(wallet_obj.receive_token(token))

@click.command(help="Accept cashu token")
@click.argument('token')
def accept(token):
    
    wallet_obj = Wallet(nsec=NSEC, relays=RELAYS, home_relay=HOME_RELAY, logging_level=LOGGING_LEVEL)
    # msg_out = wallet_obj.get_proofs()
    # wallet_obj.delete_proofs()
    # click.echo(msg_out)
    click.echo(wallet_obj.accept_token(token))

@click.command(help='monitor events')
@click.argument('nrecipient', default=None)
@click.option('--relays','-r', default="relay.openbalance.app")

def monitor(nrecipient, relays):
    relay_array = []
    click.echo(WELCOME_MSG)
    relays_str = relays.split(',')
    for each in relays_str:
        relay_array.append("wss://"+each)
    print(relay_array)
    click.echo(f"Monitoring events for {nrecipient}...")
    wallet_obj = Wallet(nsec=NSEC,relays=RELAYS,mints=MINTS,home_relay=HOME_RELAY)
    
    click.echo(wallet_obj.monitor(nrecipient, relay_array))

@click.command(help='run as a service')
@click.option('--relays','-r', default=HOME_RELAY)
def run(relays):
    # click.echo(WELCOME_MSG)
    # click.echo(f"Running as a service...")
    relay_array = []
    relays_str = relays.split(',')
    for each in relays_str:
        each = "wss://" + each if not each.startswith("wss://") else each
        relay_array.append(each)
    wallet_obj = Wallet(nsec=NSEC,relays=RELAYS,mints=MINTS,home_relay=HOME_RELAY)
    
    wallet_obj.run(relay_array)

@click.command(help='generate a payment request')
@click.argument('amount', default=21)
@click.option("--unit","-u", default="sat", help="Unit")
@click.option("--description","-d", default="payment", help="payment request description")
def request(amount, unit, description):
    click.echo(WELCOME_MSG)
    click.echo(f"generate a payment request amount {amount} {unit} with description {description}")
    wallet_obj = Wallet(nsec=NSEC,relays=RELAYS,mints=MINTS,home_relay=HOME_RELAY)
    payment_request = wallet_obj.create_payment_request(amount)
    click.echo(f"payment request {payment_request}")
    
    # wallet_obj.run()

cli.add_command(info)
cli.add_command(init)
cli.add_command(profile)
cli.add_command(replicate)
cli.add_command(post)
cli.add_command(dm)

cli.add_command(set)
cli.add_command(pay)
cli.add_command(send)
cli.add_command(get)
cli.add_command(put)
cli.add_command(share)
cli.add_command(monitor)
cli.add_command(run)
cli.add_command(request)
cli.add_command(recover)


cli.add_command(deposit)
cli.add_command(withdraw)
cli.add_command(proofs)
cli.add_command(balance)
cli.add_command(swap)
cli.add_command(delete)
cli.add_command(check)
cli.add_command(receive)
cli.add_command(accept)
cli.add_command(issue)
cli.add_command(zap)
cli.add_command(testpay)



if __name__ == "__main__":
   cli()