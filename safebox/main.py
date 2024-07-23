import asyncio, sys, click
from monstr.encrypt import Keys
from monstr.client.client import Client, ClientPool
from monstr.event.event import Event



def main():
    print("hello")

@click.command
def keys():
    k = Keys()
    print(k)


async def async_nostrpost(url, text, nsec):
    """
        Example showing how to post a text note (Kind 1) to relay
    """

    # rnd generate some keys
    n_keys = Keys(priv_k=nsec)

    async with Client(url) as c:
        n_msg = Event(kind=Event.KIND_TEXT_NOTE,
                      content=text,
                      pub_key=n_keys.public_key_hex())
        n_msg.sign(n_keys.private_key_hex())
        c.publish(n_msg)
        # await asyncio.sleep(1)

@click.command
@click.argument('url')
@click.argument('text')
@click.argument('nsec')
def nostrpost(url, text, nsec):
    asyncio.run(async_nostrpost(url,text, nsec))

@click.group()
def cli():
    pass


@click.command
@click.argument('message')
def post(message):
    click.echo(f"nostr post {message}")
   

cli.add_command(post)
cli.add_command(keys)
cli.add_command(nostrpost)

if __name__ == "__main__":
    cli()

