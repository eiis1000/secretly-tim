# bot.py
import os

import discord
from discord.ext import commands
import time
from Crypto.PublicKey import RSA
from Crypto.Hash import SHA1
from Crypto.Cipher import PKCS1_OAEP
# from Crypto.Util import Padding
import binascii
import asyncio
# from dotenv import load_dotenv

# load_dotenv()
# TOKEN = os.getenv('DISCORD_TOKEN')
TOKEN = None
with open('.env', 'r') as f:
    TOKEN = f.read().split('=')[1][1:-1]

flags = {}
start_time = time.ctime() 
prev_msg = None
personal_ads = None


intents = discord.Intents.default()
# intents = discord.Intents._from_value(2147575872)

# intents.__ior__(discord.Intents.default())
intents.message_content = True

# client = discord.Client(intents=intents)
bot = commands.Bot(command_prefix='', intents=intents)
 
# messages = []
# with open("messages.txt") as mess:
#     for line in mess:
#         line = line.strip()
#         messages.append(line)


def shorthash(s):
    h = SHA1.new()
    h.update(s.encode('utf-8'))
    return h.hexdigest()[:5]

def to_bytes(x: int) -> bytes:
    return x.to_bytes((x.bit_length() + 7) // 8, 'big')
    
def from_bytes(xbytes: bytes) -> int:
    return int.from_bytes(xbytes, 'big')

def hexit(x : int) -> str:
    return binascii.hexlify(to_bytes(x)).decode('utf-8')

def unhexit(x : str) -> int:
    return from_bytes(binascii.unhexlify(x.encode('utf-8')))

def ginct(id : int):
    num = 0
    try:
        with open(f'confession_counter_{id}', 'r') as f:
            num = int(f.read())
    except:
        pass
    with open(f'confession_counter_{id}', 'w+') as f:        
        f.write(str(num + 1))
    return num + 1

@bot.event
async def on_ready():
    print(f'Connected on {start_time} with intents {bot.intents}.')
    for guild in bot.guilds:
        await on_guild_join(guild)
    global personal_ads
    # personal_ads channel is 1060373558888505405
    # my test is 1061053785633476618
    personal_ads = bot.get_channel(1061053785633476618)
        
@bot.event
async def on_guild_join(guild):
    print(f'joined {guild}')
        


@bot.event
async def on_message(message):
    global prev_msg
    prev_msg = message
    if message.author.bot:
        return
    if message.author.id == 452902745066831903: #erez
        if 'my son' in message.content.lower():
            await message.channel.send('yes father')
    await bot.process_commands(message)

@bot.command()
async def testconfess(ctx):
    parts = ctx.message.content.split(' ', 1)
    await ctx.send('I confess that I am a bot. You said: ' + parts[1])
    
@bot.command()
async def personalconfess(ctx):
    parts = ctx.message.content.split(' ', 1)
    if not isinstance(ctx.channel, discord.DMChannel):
        await ctx.send('Please use this command in a DM.')
        await ctx.message.delete()
        return
    
    if len(parts) < 2:
        reply = await ctx.send('You forgot to include a confession. Please try again with `personalconfess CONFESSION_GOES_HERE`.')
        await asyncio.sleep(300)
        await reply.delete()
        return
    
    await personal_ads.send(f'**#{ginct(personal_ads.id)}**: {parts[1]}')
    reply = await ctx.send(f'Confession sent. This message will self-destruct in 5 minutes.')
    await asyncio.sleep(300)
    await reply.delete()

            

@bot.command()
async def keyconfess(ctx):
    parts = ctx.message.content.split(' ', 1)
    if not isinstance(ctx.channel, discord.DMChannel):
        await ctx.send('Please use this command in a DM.')
        await ctx.message.delete()
        return
    
    if len(parts) < 2:
        reply = await ctx.send('You forgot to include a confession. Please try again with `keyconfess CONFESSION_GOES_HERE`.')
        await asyncio.sleep(300)
        await reply.delete()
        return
    
    key = RSA.generate(1024)
    pubkey = hexit(key.n)
    prikey = hexit(key.d) + '_' + hexit(key.p) + '_' + hexit(key.q)
    await personal_ads.send(f'**#{ginct(personal_ads.id)}**: {parts[1]} | keyhash = {shorthash(pubkey)}, key = {pubkey}')
    reply = await ctx.send(f'Here is your private key:\n{prikey}\n**Make sure to save it somewhere safe and keep it secret!** Your confession has been sent, and this message will self-destruct in 5 minutes. If you do not save your private key, you will not be able to decrypt replies.')
    await asyncio.sleep(300)
    await reply.delete()


@bot.command()
async def encryptconfess(ctx):
    parts = ctx.message.content.split(' ', 2)
    if not isinstance(ctx.channel, discord.DMChannel):
        await ctx.send('Please use this command in a DM.')
        await ctx.message.delete()
        return
    
    if len(parts) < 3:
        reply = await ctx.send('You forgot to include content. Please try again with `encryptconfess PUBKEY_GOES_HERE REPLY_GOES_HERE`.')
        await asyncio.sleep(300)
        await reply.delete()
        return

    try:
        key = RSA.construct((unhexit(parts[1]), 65537))
        pubkey = hexit(key.n)
        unenc = parts[2].encode('utf-8')
        enc = PKCS1_OAEP.new(key).encrypt(unenc).hex()
        await personal_ads.send(f'**#{ginct(personal_ads.id)}** replying to **{shorthash(pubkey)}**: {enc}')
        reply = await ctx.send(f'Confession sent for {shorthash(pubkey)}. This message will self-destruct in 5 minutes.')
        await asyncio.sleep(300)
        await reply.delete()
    except:
        await ctx.send(f'There was an error, so \'{parts[1]}\' is probably not a valid public key. Please try again with `encryptconfess PUBKEY_GOES_HERE CONFESSION_GOES_HERE`.')
        
@bot.command()
async def identifyconfess(ctx):
    parts = ctx.message.content.split(' ', 1)
    if not isinstance(ctx.channel, discord.DMChannel):
        await ctx.send('Please use this command in a DM.')
        await ctx.message.delete()
        return
    
    if len(parts) < 2:
        reply = await ctx.send('You forgot to include a public key. Please try again with `identifyconfess PUBKEY_GOES_HERE`.')
        await asyncio.sleep(300)
        await reply.delete()
        return

    try:
        key = RSA.construct((unhexit(parts[1]), 65537))
        pubkey = hexit(key.n)
        identistr = ctx.author.name + '#' + ctx.author.discriminator + ' has identified themselves! Send them a DM :)'
        unenc = identistr.encode('utf-8')
        enc = PKCS1_OAEP.new(key).encrypt(unenc).hex()
        await personal_ads.send(f'**#{ginct(personal_ads.id)}** identifying to **{shorthash(pubkey)}**: {enc}')
        reply = await ctx.send(f'Identification sent for {shorthash(pubkey)}. This message will self-destruct in 5 minutes.')
        await asyncio.sleep(300)
        await reply.delete()
    except:
        await ctx.send(f'There was an error, so \'{parts[1]}\' is probably not a valid public key. Please try again with `encryptconfess PUBKEY_GOES_HERE CONFESSION_GOES_HERE`.')
            
@bot.command()
async def decryptconfess(ctx):
    parts = ctx.message.content.split(' ', 2)
    if not isinstance(ctx.channel, discord.DMChannel):
        await ctx.send('Please use this command in a DM.')
        await ctx.message.delete()
        return
    
    if len(parts) < 3:
        reply = await ctx.send('You forgot to include content. Please try again with `decryptconfess PRIKEY_GOES_HERE ENCRYPTED_REPLY_GOES_HERE`.')
        await asyncio.sleep(300)
        await reply.delete()
        return
    
    try:
        prikey = parts[1].split('_')
        key = RSA.construct((unhexit(prikey[1]) * unhexit(prikey[2]), 65537, unhexit(prikey[0]), unhexit(prikey[1]), unhexit(prikey[2])))
        enc = binascii.unhexlify(parts[2].encode('utf-8'))
        unenc = PKCS1_OAEP.new(key).decrypt(enc).decode('utf-8')
        reply = await ctx.send(f'The decrypted confession is:\n{unenc}\nThis message will self-destruct in 5 minutes.')
        await asyncio.sleep(300)
        await reply.delete()
    except:
        await ctx.send(f'There was an error, so \'{parts[1]}\' is probably not a valid private key. Please try again with `decryptconfess PRIKEY_GOES_HERE CONFESSION_GOES_HERE`.')
        return


@bot.command()
async def verifyconfess(ctx):
    parts = ctx.message.content.split(' ', 2)
    if not isinstance(ctx.channel, discord.DMChannel):
        await ctx.send('Please use this command in a DM.')
        await ctx.message.delete()
        return
    
    if len(parts) < 3:
        reply = await ctx.send('You forgot to include content. Please try again with `verifyconfess PRIKEY_GOES_HERE CONFESSION_GOES_HERE`.')
        await asyncio.sleep(300)
        await reply.delete()
        return

    print('here')
    try:
        prikey = parts[1].split('_')
        key = RSA.construct((unhexit(prikey[1]) * unhexit(prikey[2]), 65537, unhexit(prikey[0]), unhexit(prikey[1]), unhexit(prikey[2])))
        pubkey = hexit(key.n)
        await personal_ads.send(f'**#{ginct(personal_ads.id)}** verified as **{shorthash(pubkey)}**: {parts[2]}')
        reply = await ctx.send(f'Verification as {shorthash(pubkey)} succeeded. This message will self-destruct in 5 minutes.')
        await asyncio.sleep(300)
        await reply.delete()
    except:
        await ctx.send(f'There was an error, so \'{parts[1]}\' is probably not a valid private key. Please try again with `decryptconfess PRIKEY_GOES_HERE CONFESSION_GOES_HERE`.')
        return


bot.run(TOKEN)
