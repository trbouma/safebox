import asyncio, sys, click, os, yaml
from monstr.encrypt import Keys
from monstr.client.client import Client, ClientPool
from monstr.event.event import Event
from safebox.wallet import Wallet
from safebox.models import nostrProfile, SafeboxItem
from datetime import datetime
from safebox.wallet import Wallet
from safebox.lightning import lightning_address_pay

relays  = ["wss://nostr-pub.wellorder.net", "wss://relay.damus.io"]
mints   = ["https://8333.space:8333"]
wallet  = "default" 

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
    config_obj = {'nsec': 'notset', 'relays': relays, "mints": mints, "wallet": wallet}
    with open(file_path, 'w') as file:        
        yaml.dump(config_obj, file)

RELAYS  = config_obj['relays']
NSEC    = config_obj['nsec']
MINTS   = config_obj['mints']
WALLET  = config_obj['wallet']

def write_config():
     with open(file_path, 'w') as file:        
        yaml.dump(config_obj, file)



@click.group()
def cli():
    pass

@click.command()
@click.pass_context
def info(ctx):
    click.echo("This is safebox. Retrieving wallet...")
    wallet_obj = Wallet(NSEC,RELAYS,MINTS)
    print(wallet_obj)

@click.command(help="initialize a new safebox")
def init():
    click.echo("Creating a new safebox")
    wallet_obj = Wallet(NSEC, RELAYS, MINTS)
    config_obj['nsec'] = wallet_obj.create_profile()
    click.echo(f"nsec: {config_obj['nsec']}")
    write_config()
    click.echo(wallet_obj.get_post())
    


@click.command(help="set local config options")
@click.option('--nsec', '-n', default=None, help='set nsec')
@click.option('--relays', '-r', default=None, help='set relays')
@click.option('--mints', '-m', default=None, help='set mints')
@click.option('--wallet', '-w', default=None, help='set wallet')
def set(nsec, relays, mints, wallet):
    if nsec == None and relays == None and mints == None and wallet==None:
        click.echo(yaml.dump(config_obj, default_flow_style=False))
        return
   

    if nsec != None:
        config_obj['nsec']=nsec
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


@click.command()
# @click.option('--nsec', '-n', help='nsec for wallet')
def profile():
    wallet = Wallet(NSEC, RELAYS, MINTS)
    nostr_profile = wallet.get_profile()
    click.echo(f"npub: {str(wallet.pubkey_bech32)}")
    click.echo(f"nsec: {str(wallet.k.private_key_bech32())}")
    click.echo("-"*80)
    for key, value in nostr_profile.items():
        
        click.echo(f"{str(key).ljust(15)}: {value}")
    click.echo("-"*80)
    click.echo(wallet.get_post())
    click.echo("-"*80)
    # click.echo(wallet.get_proofs())

@click.command(help='help for getwalletinfo')
@click.argument('label', default = "default")
def get(label):
    
    
    wallet_obj = Wallet(NSEC, RELAYS, MINTS)

    try:
        wallet_info = wallet_obj.get_wallet_info(label)

    except:
        wallet_info = "No label found!"
    
    click.echo(wallet_info)

@click.command(help='help for put')
@click.argument('label', default='default')
@click.argument('label_info', default='hello')
# @click.option('--label', '-l', default = "default", help='label name')
@click.option('--mints', '-m', help='list of mints')

def put(label, mints, label_info):
    jsons=None
    wallet_obj = Wallet(NSEC, RELAYS, MINTS)
    # click.echo(wallet.get_wallet_info())
    click.echo(wallet)
    if mints != None:
        mint_array = str(mints).replace(" ","").split(',')
        # click.echo(mints if "https://" in mint else "https://"+mint)
        click.echo(mint_array)
    else:
        mint_array = config_obj['mints']
    
    wallet_info_now = f"test time {datetime.now()}"
    

    if wallet != None:
        wallet_name = wallet
    else:
        wallet_name = config_obj['wallet']
        print("wallet_name", wallet)
    
    relay_array = config_obj['relays']
    wallet_obj.set_wallet_info(label, label_info=label_info)

@click.command(help='Do a post')
@click.option('--message','-m', default='hello world')
def post(message):
    click.echo(message)
    wallet_obj = Wallet(NSEC, RELAYS, MINTS)
    wallet_obj.send_post(message)

@click.command(help='help for setindexinfo')
@click.option('--jsons', '-j', default = '{}', help='json string')
def setindexinfo(jsons):
    click.echo("setindex info")
    wallet_obj = Wallet(NSEC, RELAYS)
    wallet_obj.set_index_info(jsons)

@click.command(help='help for getindexinfo')
def index():
    click.echo("getindex info")
    wallet_obj = Wallet(NSEC, RELAYS)
    index_out = wallet_obj.get_index_info()
    if index_out:
        click.echo(index_out)
    else:
        click.echo("No index!")

@click.command(help='help for getindexinfo')
def additem():
    click.echo("add safebox item")
    safe_box_item = SafeboxItem(name="test",type="note",description="test")
    print(safe_box_item.gethash())
    wallet_obj = Wallet(NSEC, RELAYS)
    index_out = wallet_obj.add_item(safe_box_item)
    click.echo(index_out)

@click.command(help="Deposit funds into wallet")
@click.argument('amount')
def deposit(amount: int):
    click.echo(f"amount: {amount}")
    wallet_obj = Wallet(NSEC, RELAYS,MINTS)
    msg_out = wallet_obj.deposit(amount)
    click.echo(msg_out)
    click.echo(f"Please run {__name__.split(".")[0]} check to see if invoice is paid")
    
@click.command(help="Check for payment")
def check():
    wallet_obj = Wallet(NSEC, RELAYS,MINTS)
    msg_out = wallet_obj.check()
    click.echo(msg_out)

@click.command(help="Payout funds to lightning address")
@click.argument('amount', default=21)
@click.argument('lnaddress', default='trbouma@openbalance.app')
@click.option('--comment','-c', default='Paid!')
def pay(amount,lnaddress: str, comment:str):
    click.echo(f"Pay to: {lnaddress}")
    wallet_obj = Wallet(NSEC, RELAYS,MINTS)
    wallet_obj.pay(amount,lnaddress,comment)
    
    
    #click.echo(msg_out)

@click.command(help='Delete proofs')
def delete():
    wallet_obj = Wallet(NSEC, RELAYS, MINTS)
    wallet_obj.delete_proofs()
    

@click.command(help="List proofs")
def proofs():
    
    wallet_obj = Wallet(NSEC, RELAYS, MINTS)
    # msg_out = wallet_obj.get_proofs()
    # wallet_obj.delete_proofs()
    # click.echo(msg_out)
    click.echo(f"{wallet_obj.balance} sats in {len(wallet_obj.proofs)} proofs in {wallet_obj.events} events")
    for each in wallet_obj.proofs:
        click.echo(f"id: {each.id} amount: {each.amount} secret: {each.secret}")
    click.echo(f"{wallet_obj.powers_of_2_sum(wallet_obj.balance)}")

@click.command(help="Show balance")
def balance():
    
    wallet_obj = Wallet(NSEC, RELAYS, MINTS)

    click.echo(f"{wallet_obj.balance} sats in {len(wallet_obj.proofs)} proofs in {wallet_obj.events} events")


@click.command(help="Swap proofs")
def swap():
    
    wallet_obj = Wallet(NSEC, RELAYS, MINTS)
    # msg_out = wallet_obj.get_proofs()
    # wallet_obj.delete_proofs()
    # click.echo(msg_out)
    click.echo(wallet_obj.swap())

@click.command(help="Receive cashu token")
@click.argument('token')
def receive(token):
    
    wallet_obj = Wallet(NSEC, RELAYS, MINTS)
    # msg_out = wallet_obj.get_proofs()
    # wallet_obj.delete_proofs()
    # click.echo(msg_out)
    click.echo(wallet_obj.receive_token(token))

cli.add_command(info)
cli.add_command(init)
cli.add_command(profile)
cli.add_command(post)

cli.add_command(set)
cli.add_command(pay)
cli.add_command(get)
cli.add_command(put)
cli.add_command(setindexinfo)
cli.add_command(index)
cli.add_command(additem)
cli.add_command(deposit)
cli.add_command(proofs)
cli.add_command(balance)
cli.add_command(swap)
cli.add_command(delete)
cli.add_command(check)
cli.add_command(receive)



if __name__ == "__main__":
   cli()