import asyncio, sys, click, os, yaml
from monstr.encrypt import Keys
from monstr.client.client import Client, ClientPool
from monstr.event.event import Event
from safebox.wallet import Wallet
from safebox.models import nostrProfile, SafeboxItem
from datetime import datetime
from safebox.wallet import Wallet
from safebox.lightning import lightning_address_pay
from time import sleep

relays  = [ "wss://relay.nimo.cash",
            "wss://nostr-pub.wellorder.net", 
            "wss://relay.damus.io", 
            "wss://relay.primal.net",
            "wss://nos.lol"
        ]
mints   = ["https://mint.belgianbitcoinembassy.org"]
wallet  = "default" 
home_relay = "wss://relay.magiccity.live"
replicate_relays = ["wss://relay.nimo.cash", "wss://nostr-pub.wellorder.net"]

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

def write_config():
     with open(file_path, 'w') as file:        
        yaml.dump(config_obj, file)



@click.group()
def cli():
    pass

@click.command(help='display info')
@click.pass_context
def info(ctx):
    click.echo("This is safebox. Retrieving wallet...")
    wallet_obj = Wallet(nsec=NSEC,relays=RELAYS,mints=MINTS, home_relay=HOME_RELAY)
    print(wallet_obj)

@click.command(help="initialize a new safebox")
def init():
    click.echo(f"Creating a new safebox with {MINTS}")
    wallet_obj = Wallet(nsec=NSEC, relays=RELAYS, mints=MINTS, home_relay=HOME_RELAY)
    config_obj['nsec'] = wallet_obj.create_profile()
    click.echo(f"nsec: {config_obj['nsec']}")
    write_config()
    click.echo(wallet_obj.get_post())
    


@click.command(help="set local config options")
@click.option('--nsec', '-n', default=None, help='set nsec')
@click.option('--relays', '-r', default=None, help='set relays')
@click.option('--home', '-h', default=None, help='set home relay')
@click.option('--mints', '-m', default=None, help='set mints')
@click.option('--wallet', '-w', default=None, help='set wallet')
@click.option('--xrelays', '-x', default=None, help='set replicate relays')
def set(nsec, home, relays, mints, wallet, xrelays):
    
    if nsec == None and relays == None and mints == None and home == None and wallet==None and xrelays==None:
        click.echo(yaml.dump(config_obj, default_flow_style=False))
        return
   

    if nsec != None:
        config_obj['nsec']=nsec

    
    if home != None:
        home_relay = home if "wss://" in home else f"wss://{home}"
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

    if wallet != None:
        config_obj['wallet'] = wallet
    else:
        config_obj['wallet'] = WALLET

    # print(config_obj)
    click.echo(yaml.dump(config_obj,default_flow_style=False))
    with open(file_path, 'w') as file:        
        yaml.dump(config_obj, file)


@click.command(help='display nostr profile')

def profile():
    wallet = Wallet(nsec=NSEC,relays=RELAYS, home_relay=HOME_RELAY,mints=MINTS)
    
    # click.echo(replicate)
    click.echo(wallet.get_profile())
    click.echo(wallet.get_post())

@click.command(help='replicate safebox data to other relays')
def replicate():
    wallet = Wallet(nsec=NSEC,relays=RELAYS, home_relay=HOME_RELAY)
    print("REPLICATE RELAYS:", REPLICATE_RELAYS)
    click.echo(wallet.replicate_safebox(REPLICATE_RELAYS))
    # click.echo(replicate)
    
       



@click.command(help='get a private wallet record')
@click.argument('label', default = "default")
def get(label):
    
    
    wallet_obj = Wallet(nsec=NSEC, relays=RELAYS, home_relay=HOME_RELAY)

    try:
        safebox_info = wallet_obj.get_wallet_info(label)

    except:
        safebox_info = "No label found!"
    
    click.echo(safebox_info)

@click.command(help='help for put')
@click.argument('label', default='default')
@click.argument('label_info', default='hello')



def put(label, label_info):
    jsons=None
    wallet_obj = Wallet(nsec=NSEC, relays=RELAYS, home_relay=HOME_RELAY)
    # click.echo(wallet.get_wallet_info())
    click.echo(wallet)

    if label in ["mints", "relay", "quote", "passphrase", "profile"]:
        click.echo("Warning! This label is reserved for system use.")    

    if click.confirm('Do you want to continue?'):    
     wallet_obj.set_wallet_info(label, label_info=label_info)

@click.command(help='Do a post')
@click.argument('message', default="Hello, World!")

def post(message):
    click.echo(message)
    wallet_obj = Wallet(nsec=NSEC, relays=RELAYS, home_relay=HOME_RELAY)
    wallet_obj.send_post(message)







@click.command(help="deposit funds into wallet via lightning invoice")
@click.argument('amount')
def deposit(amount: int):
    click.echo(f"amount: {amount}")
    wallet_obj = Wallet(nsec=NSEC, relays=RELAYS,mints=MINTS,home_relay=HOME_RELAY)
    cli_quote = wallet_obj.deposit(amount)
    click.echo(f"\n\nPlease pay invoice:\n {cli_quote.invoice}") 

    click.echo(f"\n\nPlease run safebox check invoice check to see if invoice is paid")
    
@click.command(help="Check for payment")
@click.argument('param')

def check(param):
    wallet_obj = Wallet(nsec=NSEC, relays=RELAYS, home_relay=HOME_RELAY)
    if param == "invoice":
        click.echo("check invoice")        
        msg_out = wallet_obj.check()
        click.echo(msg_out)
    elif param == "ecash":
        click.echo("check for ecash")
        msg_out = wallet_obj.get_dm()
        
        click.echo(msg_out)

@click.command(help="Payout funds to lightning address")
@click.argument('amount', default=21)
@click.argument('lnaddress', default='trbouma@openbalance.app')
@click.option('--comment','-c', default='Paid!')
def pay(amount,lnaddress: str, comment:str):
    click.echo(f"Pay to: {lnaddress}")
    wallet_obj = Wallet(nsec=NSEC, home_relay=HOME_RELAY, relays=RELAYS,mints=MINTS)
    wallet_obj.pay_multi(amount,lnaddress,comment)
    # wallet_obj.swap_multi_consolidate()

@click.command(help="Test pay amount")
@click.argument('amount', default=21)
def testpay(amount):
    
    wallet_obj = Wallet(nsec=NSEC, home_relay=HOME_RELAY, relays=RELAYS,mints=MINTS)
    click.echo(wallet_obj.testpay(amount=amount))
    

@click.command(help="Issue token amount")
@click.argument('amount', default=1)
def issue(amount:int):
    click.echo(f"Issue token amount: {amount}")
    wallet_obj = Wallet(nsec=NSEC, relays=RELAYS,mints=MINTS,home_relay=HOME_RELAY)
    click.echo(wallet_obj.issue_token(amount))

@click.command(help="Zap amount to event or to recipient")
@click.argument('amount', default=1)
# @click.argument('event_id')
@click.option('--event','-e', default=None)
@click.option('--npub','-n', default=None)
@click.option('--comment','-c', default='⚡️')
def zap(amount:int, event,npub, comment):
    if npub:
        click.echo("Zap to recipient {npub}, ignore event")
        return
    if event == None:
        click.echo("Need an event!")
        return

    click.echo(f"Zap amount: {amount} to {event}")
    wallet_obj = Wallet(nsec=NSEC, relays=RELAYS,home_relay=HOME_RELAY)
    click.echo(wallet_obj.zap(amount,event,comment))
    
    
    
    

@click.command(help='Delete proofs')
def delete():
    if click.confirm("Are you really sure?"):
        click.echo("Deleting proofs...")
        wallet_obj = Wallet(nsec=NSEC, relays=RELAYS, mints=MINTS, home_relay=HOME_RELAY)
        wallet_obj.delete_proofs()
    

@click.command(help="list proofs")
def proofs():
    
    wallet_obj = Wallet(nsec=NSEC, relays=RELAYS, home_relay=HOME_RELAY)
    # msg_out = wallet_obj.get_proofs()
    # wallet_obj.delete_proofs()
    # click.echo(msg_out)
    click.echo(f"{wallet_obj.balance} sats in {len(wallet_obj.proofs)} proofs in {wallet_obj.events} events")
    for each in wallet_obj.proofs:
        click.echo(f"id: {each.id} amount: {each.amount} Y: {each.Y}")
    click.echo(f"{wallet_obj.powers_of_2_sum(wallet_obj.balance)}")
    click.echo("Proofs by keyset")
    wallet_obj._proofs_by_keyset()


@click.command(help="show balance")
def balance():
    
    wallet_obj = Wallet(nsec=NSEC, relays=RELAYS, home_relay=HOME_RELAY)

    click.echo(f"{wallet_obj.balance} sats in {len(wallet_obj.proofs)} proofs in {wallet_obj.events} events")


@click.command(help="swap proofs for new proofs")
def swap():
    
    wallet_obj = Wallet(nsec=NSEC, relays=RELAYS, mints=MINTS, home_relay=HOME_RELAY)
    # msg_out = wallet_obj.get_proofs()
    # wallet_obj.delete_proofs()
    # click.echo(msg_out)
    # click.echo(wallet_obj.swap_multi_each())
    click.echo(wallet_obj.swap_multi_consolidate())

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
    
    wallet_obj = Wallet(nsec=NSEC, relays=RELAYS, home_relay=HOME_RELAY)
    # msg_out = wallet_obj.get_proofs()
    # wallet_obj.delete_proofs()
    # click.echo(msg_out)
    click.echo(wallet_obj.accept_token(token))

cli.add_command(info)
cli.add_command(init)
cli.add_command(profile)
cli.add_command(replicate)
cli.add_command(post)

cli.add_command(set)
cli.add_command(pay)
cli.add_command(get)
cli.add_command(put)



cli.add_command(deposit)
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