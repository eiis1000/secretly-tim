# bot.py
import os

import discord
from discord.ext import commands
import time
from Crypto.PublicKey import RSA
from Crypto.Hash import SHA1
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Protocol.SecretSharing import Shamir
from Crypto.Util import Padding
import binascii
import asyncio
import base64
import sys
import re
import traceback
# from dotenv import load_dotenv

# load_dotenv()
# TOKEN = os.getenv('DISCORD_TOKEN')
TOKEN = None
tokenfile = '.token'
if len(sys.argv) > 1:
    tokenfile = sys.argv[1] + '.token'
with open(tokenfile, 'r') as f:
    TOKEN = f.read().strip()

pan = 1060373558888505405 # personal ads
# pan = 1061053785633476618 # test
flags = {}
start_time = time.ctime() 
prev_msg = None
personal_ads = None
to_delete = {}

mods = {}
pubfolder = './pubkeys/'
if len(sys.argv) > 1:
    pubfolder = sys.argv[1] + 'pubkeys/'
pubkeysdir = os.fsencode(pubfolder)
for file in os.listdir(pubkeysdir):
    filename = os.fsdecode(file)
    with open(pubfolder + filename, 'r') as f:
        pubkey = f.read()
        mods[filename[:-4]] = pubkey


# intents = discord.Intents.default()
intents = discord.Intents._from_value(3276541)

# intents.__ior__(discord.Intents.default())
# intents.message_content = True

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

def hexit(x: int) -> str:
    return binascii.hexlify(to_bytes(x)).decode('utf-8')

def unhexit(x: str) -> int:
    return from_bytes(binascii.unhexlify(x.encode('utf-8')))

def ginct(id: int):
    num = 0
    cfile = f'confession_counter_{id}'
    if len(sys.argv) > 1:
        cfile = sys.argv[1] + cfile
    try:
        with open(cfile, 'r') as f:
            num = int(f.read())
    except:
        pass
    with open(cfile, 'w+') as f:        
        f.write(str(num + 1))
    return num + 1

async def logconfess(num: int, confessor: discord.User, ctype: str):
    global mods
    salt = os.urandom(16).hex()
    secret = f'{ctype} #{num} by {confessor.name}#{confessor.discriminator} ({confessor.id}) on {time.ctime()} (ignore: {salt})'
    secret = Padding.pad(secret.encode('utf-8'), 16)
    secret_chunks = [secret[i:i+16] for i in range(0, len(secret), 16)]
    split_chunks = [[str(k[0]) + ';' + k[1].hex() for k in Shamir.split(len(mods) // 2 + 1, len(mods), chunk)] for chunk in secret_chunks]
    i = 0
    for (mod, key) in mods.items():
        key = RSA.import_key(key)
        cipher = PKCS1_OAEP.new(key)
        enc_data = cipher.encrypt(b';;'.join([secrets[i].encode('utf-8') for secrets in split_chunks]))
        mod = await bot.fetch_user(int(mod))
        await mod.send(f'Identity fragment of {ctype} #{num} encrypted with {mod.name}\'s public key:\n||{base64.b64encode(enc_data).decode("utf-8")}||')
        i += 1

async def sendlogsleepdelete(ctx, type, cnum, time, logme, msg):
    try:
        reply = await ctx.send(msg)
        if logme:
            await logconfess(cnum, ctx.author, type)
        to_delete[reply.id] = reply
        await asyncio.sleep(time)
        await reply.delete()
        del to_delete[reply.id]
    except Exception as e:
        print('error in sendlogsleepdelete')
        print(e)
        sendlogsleepdelete(ctx, None, None, 300, False, 'Error in send-encryptlog-sleep-delete routine. Please report to the bot owner before this message deletes itself in 5 minutes.')
        print(traceback.format_exc())
        sendlogsleepdelete(ctx, None, None, 300, False, f'Attempting to attach traceback: \\{traceback.format_exc()[0:600]}\\...\\{traceback.format_exc()[-600:]}\\')

async def check_access(ctx):
    try: 
        if personal_ads.guild.get_member(ctx.author.id).permissions_in(personal_ads).read_messages:
            return True
        await sendlogsleepdelete(ctx, None, None, 300, False, 'You do not have access to #personal-ads.')
        return False
    except Exception as e:
        print('error in check_access, allowing access anyways')
        print(e)
        return True

@bot.event
async def on_ready():
    print(f'Connected on {start_time} with intents {bot.intents}.')
    for guild in bot.guilds:
        await on_guild_join(guild)
    global personal_ads
    personal_ads = bot.get_channel(pan) # personal_ads
        
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
        if message.content.lower() == 'version' or message.content.lower() == 'pbv':
            await message.channel.send('1.1.12')
        if message.content.lower() == 'kill yourself' or message.content.lower() == 'kys':
            await message.channel.send('okay :(')
            try:
                for m in to_delete.values():
                    await m.delete()
                await bot.close()
                print("committed suicide")
            except:
                exit(0)
    await bot.process_commands(message)

# @bot.command()
# async def testconfess(ctx):
#     parts = re.split('\s+', ctx.message.content, 1)
#     await ctx.send('I confess that I am a bot. You said: ' + parts[1])
    
@bot.command()
async def personalconfess(ctx):
    parts = re.split('\s+', ctx.message.content, 1)
    # if not isinstance(ctx.channel, discord.DMChannel):
    #     await ctx.send('Please use this command in a DM.')
    #     await ctx.message.delete()
    #     return
    
    if len(parts) < 2:
        await sendlogsleepdelete(ctx, None, None, 300, False, 'You forgot to include a confession. Please try again with `personalconfess CONFESSION_GOES_HERE`.')
    
    cnum = ginct(personal_ads.id)
    await personal_ads.send(f'**#{cnum}** unencrypted: {parts[1]}')
    await sendlogsleepdelete(ctx, parts[0], cnum, 300, True, f'Confession sent. For your own security, please delete your message. This message will self-destruct in 5 minutes.')

            

@bot.command()
async def keyconfess(ctx):
    parts = re.split('\s+', ctx.message.content, 1)
    if not isinstance(ctx.channel, discord.DMChannel):
        await ctx.send('Please use this command in a DM.')
        await ctx.message.delete()
        return
    if not await check_access(ctx):
        return
    
    if len(parts) < 2:
        await sendlogsleepdelete(ctx, None, None, 300, False, 'You forgot to include a confession. Please try again with `keyconfess CONFESSION_GOES_HERE`.')
    
    key = RSA.generate(1024)
    pubkey = hexit(key.n)
    prikey = hexit(key.d) + '_' + hexit(key.p) + '_' + hexit(key.q)
    cnum = ginct(personal_ads.id)
    await personal_ads.send(f'**#{cnum}** starting **{shorthash(pubkey)}**: {parts[1]} | keyhash = {shorthash(pubkey)}, pubkey = ||{pubkey}||')
    await sendlogsleepdelete(ctx, parts[0], cnum, 300, True, f'Your private key is in the following spoilers. **Make sure to save it somewhere safe and keep it secret!**\n||{prikey}||\nFor your own security, please delete your message. This message will self-destruct in **5 minutes**. **If you do not save your private key, you will not be able to decrypt replies.**')

@bot.command()
async def encryptconfess(ctx):
    parts = re.split('\s+', ctx.message.content, 2)
    if not isinstance(ctx.channel, discord.DMChannel):
        await ctx.send('Please use this command in a DM.')
        await ctx.message.delete()
        return
    if not await check_access(ctx):
        return
    
    if len(parts) < 3:
        await sendlogsleepdelete(ctx, None, None, 300, False, 'You forgot to include content. Please try again with `encryptconfess PUBKEY_GOES_HERE REPLY_GOES_HERE`.')

    if len(parts[2]) > 300:
        await sendlogsleepdelete(ctx, None, None, 300, False, 'Your reply is too long; it must be under 300 characters. Please try again with a shorter reply.')
        return
    
    try:
        key = RSA.construct((unhexit(parts[1]), 65537))
        pubkey = hexit(key.n)
        # print(parts[2].encode('utf-8'), len(parts[2].encode('utf-8')), 64 - len(parts[2].encode('utf-8'))%64)
        secret = Padding.pad(parts[2].encode('utf-8'), 64)
        secret_chunks = [secret[i:i+64] for i in range(0, len(secret), 64)]
        enc = '_'.join([PKCS1_OAEP.new(key).encrypt(unenc).hex() for unenc in secret_chunks])
        cnum = ginct(personal_ads.id)
        await personal_ads.send(f'**#{cnum}** replying to **{shorthash(pubkey)}** encrypted: ||{enc}||')
        await sendlogsleepdelete(ctx, parts[0], cnum, 300, True, f'Confession sent for {shorthash(pubkey)}. For your own security, please delete your message. This message will self-destruct in 5 minutes.')
    except:
        await sendlogsleepdelete(ctx, None, None, 300, False, f'There was an error, so \'{parts[1]}\' is probably not a valid public key. Please try again with `encryptconfess PUBKEY_GOES_HERE CONFESSION_GOES_HERE`.')
        
@bot.command()
async def identifyconfess(ctx):
    parts = re.split('\s+', ctx.message.content, 1)
    if not isinstance(ctx.channel, discord.DMChannel):
        await ctx.send('Please use this command in a DM.')
        await ctx.message.delete()
        return
    if not await check_access(ctx):
        return
    
    if len(parts) < 2:
        await sendlogsleepdelete(ctx, None, None, 300, False, 'You forgot to include a public key. Please try again with `identifyconfess PUBKEY_GOES_HERE`.')

    try:
        key = RSA.construct((unhexit(parts[1]), 65537))
        pubkey = hexit(key.n)
        identistr = ctx.author.name + '#' + ctx.author.discriminator + ' has identified themselves! Send them a DM :)'
        secret = Padding.pad(identistr.encode('utf-8'), 64)
        secret_chunks = [secret[i:i+64] for i in range(0, len(secret), 64)]
        enc = '_'.join([PKCS1_OAEP.new(key).encrypt(unenc).hex() for unenc in secret_chunks])
        cnum = ginct(personal_ads.id)
        await personal_ads.send(f'**#{cnum}** identifying to **{shorthash(pubkey)}** encrypted: ||{enc}||')
        await sendlogsleepdelete(ctx, parts[0], cnum, 300, True, f'Identification sent for {shorthash(pubkey)}. For your own security, please delete your message. This message will self-destruct in 5 minutes.')
    except:
        await sendlogsleepdelete(ctx, None, None, 300, False, f'There was an error, so \'{parts[1]}\' is probably not a valid public key. Please try again with `encryptconfess PUBKEY_GOES_HERE CONFESSION_GOES_HERE`.')
            

@bot.command()
async def identityconfess(ctx):
    await sendlogsleepdelete(ctx, None, None, 300, False, 'The correct command is identi**f**yconfess. Try that :)')

@bot.command()
async def decryptconfess(ctx):
    parts = re.split('\s+', ctx.message.content, 2)
    if not isinstance(ctx.channel, discord.DMChannel):
        await ctx.send('Please use this command in a DM.')
        await ctx.message.delete()
        return
    
    if len(parts) < 3:
        await sendlogsleepdelete(ctx, None, None, 300, False, 'You forgot to include content. Please try again with `decryptconfess PRIKEY_GOES_HERE ENCRYPTED_REPLY_GOES_HERE`.')
    
    try:
        prikey = parts[1].split('_')
        key = RSA.construct((unhexit(prikey[1]) * unhexit(prikey[2]), 65537, unhexit(prikey[0]), unhexit(prikey[1]), unhexit(prikey[2])))
        enc_chunks = [bytes.fromhex(a) for a in parts[2].split('_')]
        unenc_joined = b''.join([PKCS1_OAEP.new(key).decrypt(chunk) for chunk in enc_chunks])
        unenc = Padding.unpad(unenc_joined, 64).decode('utf-8')
        await sendlogsleepdelete(ctx, None, None, 300, False, f'The decrypted confession is:\n{unenc}\nFor your own security, please delete your message. This message will self-destruct in 5 minutes.')
    except:
        await sendlogsleepdelete(ctx, None, None, 300, False, f'There was an error, so \'{parts[1]}\' is probably the wrong key or not a valid private key. Please try again with `decryptconfess PRIKEY_GOES_HERE CONFESSION_GOES_HERE`.')
        return

@bot.command()
async def decrypt(ctx):
    await decryptconfess(ctx)

@bot.command()
async def verifyconfess(ctx):
    parts = re.split('\s+', ctx.message.content, 2)
    if not isinstance(ctx.channel, discord.DMChannel):
        await ctx.send('Please use this command in a DM.')
        await ctx.message.delete()
        return
    if not await check_access(ctx):
        return
    
    if len(parts) < 3:
        await sendlogsleepdelete(ctx, None, None, 300, False, 'You forgot to include content. Please try again with `verifyconfess PRIKEY_GOES_HERE CONFESSION_GOES_HERE`.')

    print('here')
    try:
        prikey = parts[1].split('_')
        key = RSA.construct((unhexit(prikey[1]) * unhexit(prikey[2]), 65537, unhexit(prikey[0]), unhexit(prikey[1]), unhexit(prikey[2])))
        pubkey = hexit(key.n)
        cnum = ginct(personal_ads.id)
        await personal_ads.send(f'**#{cnum}** verified as **{shorthash(pubkey)}**: {parts[2]}')
        await sendlogsleepdelete(ctx, parts[0], cnum, 300, True, f'Verification as {shorthash(pubkey)} succeeded. For your own security, please delete your message. This message will self-destruct in 5 minutes.')
    except:
        await sendlogsleepdelete(ctx, None, None, 300, False, f'There was an error, so \'{parts[1]}\' is probably not a valid private key. Please try again with `decryptconfess PRIKEY_GOES_HERE CONFESSION_GOES_HERE`.')
        return

@bot.command()
async def deconfess(ctx):
    parts = re.split('\s+', ctx.message.content)
    partparts = [p.split(';;') for p in parts[1:]]
    partparttuples = [[(int(p.split(';')[0]), bytes.fromhex(p.split(';')[1])) for p in l] for l in partparts]
    tppt = [list(i) for i in zip(*partparttuples)]
    m0 = Shamir.combine([(int(k.split(';')[0]), bytes.fromhex(k.split(';')[1])) for k in parts[1:]])
    m = b''.join([Shamir.combine(l) for l in tppt])
    try:
        m = m.decode('utf-8')
        await ctx.send('Deconfessed:\n' + m)
    except:
        await ctx.send('Invalid UTF-8 string; you probably didn\'t use the right number of shares. Bytes: ' + m.hex())

@bot.command()
async def deletedm(ctx):
    parts = re.split('\s+', ctx.message.content, 1)
    if not isinstance(ctx.channel, discord.DMChannel):
        await ctx.send('Please use this command in a DM.')
        await ctx.message.delete()
        return
    
    if len(parts) < 2:
        await sendlogsleepdelete(ctx, None, None, 300, False, 'You forgot to include a message ID. Please try again with `delete MESSAGE_ID_GOES_HERE`.')
        return
    
    try:
        mid = None
        if ('-' in parts[1]):
            mid = int(parts[1].split('-')[1])
        else:
            mid = int(parts[1])
        msg = await ctx.fetch_message(mid)
        if (msg.channel != ctx.channel):
            await sendlogsleepdelete(ctx, None, None, 30, False, 'You can only delete messages sent in this DM. This message will self-destruct in 30 seconds.')
            return
        if (msg.author != bot.user):
            await sendlogsleepdelete(ctx, None, None, 30, False, 'You can only delete messages sent by this bot. This message will self-destruct in 30 seconds.')
            return
        await msg.delete()
        await sendlogsleepdelete(ctx, None, None, 30, False, 'Message deleted. This message will self-destruct in 30 seconds.')
    except:
        await sendlogsleepdelete(ctx, None, None, 30, False, 'Message not found in this DM. This message will self-destruct in 30 seconds.')
    
@bot.command()
async def deleteverified(ctx):
    parts = re.split('\s+', ctx.message.content, 2)
    if not isinstance(ctx.channel, discord.DMChannel):
        await ctx.send('Please use this command in a DM.')
        await ctx.message.delete()
        return
    
    if len(parts) < 3:
        await sendlogsleepdelete(ctx, None, None, 300, False, 'You forgot to include content. Please try again with `deleteconfess PRIKEY_GOES_HERE MESSAGE_ID_GOES_HERE`.')
        return
    
    try:
        mid = None
        if ('-' in parts[2]):
            mid = int(parts[2].split('-')[1])
        else:
            mid = int(parts[2])
        msg = await personal_ads.fetch_message(mid)
        if (msg.author != bot.user):
            await sendlogsleepdelete(ctx, None, None, 30, False, 'You can only delete messages sent by this bot. This message will self-destruct in 30 seconds.')
            return
        prikey = parts[1].split('_')
        key = RSA.construct((unhexit(prikey[1]) * unhexit(prikey[2]), 65537, unhexit(prikey[0]), unhexit(prikey[1]), unhexit(prikey[2])))
        pubkey = hexit(key.n)
        if not re.compile(f'^\*\*#\d+\*\*\s(verified\s)?as\s\*\*{shorthash(pubkey)}').match(msg.content):
            await sendlogsleepdelete(ctx, None, None, 30, False, 'You can only delete messages verified as you. This message will self-destruct in 30 seconds.')
            return
        new_content = msg.content.split(":")[0] + f" Confession deleted via `deleteverified` on {time.ctime()}."
        await msg.edit(content=new_content)
        await sendlogsleepdelete(ctx, None, None, 30, False, 'Confession content deleted. This message will self-destruct in 30 seconds.')
    except:
        await sendlogsleepdelete(ctx, None, None, 30, False, 'Message not found in #personal-ads. This message will self-destruct in 30 seconds.')
        
        
@bot.command()
async def testkey(ctx):
    parts = re.split('\s+', ctx.message.content, 1)
    if not isinstance(ctx.channel, discord.DMChannel):
        await ctx.send('Please use this command in a DM.')
        await ctx.message.delete()
        return
    
    if len(parts) < 2:
        await sendlogsleepdelete(ctx, None, None, 300, False, 'You forgot to include a key. Please try again with `testkey PRIKEY_GOES_HERE`.')
        return
    
    try:
        pubkey = parts[1].split('_')
        key = RSA.construct((unhexit(pubkey[1]) * unhexit(pubkey[2]), 65537, unhexit(pubkey[0]), unhexit(pubkey[1]), unhexit(pubkey[2])))
        await sendlogsleepdelete(ctx, None, None, 300, False, f'Your private key corresponds to the public key with hash **{shorthash(hexit(key.n))}** and value ||{hexit(key.n)}||.')
    except:
        await sendlogsleepdelete(ctx, None, None, 300, False, 'Key is invalid.')


bot.remove_command('help')
@bot.command()
async def help(ctx):
    help_str = '''Commands (all commands are DM only):
`keyconfess CONFESSION_GOES_HERE` - Confess with a public key
`encryptconfess PUBKEY_GOES_HERE REPLY_GOES_HERE` - Reply to a confession with an encrypted message
`identifyconfess PUBKEY_GOES_HERE` - Identify yourself in an encrypted confession
`decryptconfess PRIKEY_GOES_HERE ENCRYPTED_REPLY_GOES_HERE` - Decrypt an encrypted confession
`verifyconfess PRIKEY_GOES_HERE CONFESSION_GOES_HERE` - Confess while verifying that you are the same person
`deletedm MESSAGE_ID_GOES_HERE` - Delete a message sent by this bot in DMs
`deleteverified PRIKEY_GOES_HERE MESSAGE_ID_GOES_HERE` - Delete a verified message sent by this bot in #personal-ads
`testkey PRIKEY_GOES_HERE` - Test a private key to see which public key it corresponds to
    '''
    if not isinstance(ctx.channel, discord.DMChannel):
        await ctx.send('Please use this command in a DM.')
    else:
        await sendlogsleepdelete(ctx, None, None, 300, False, help_str + '\nThis message will self-destruct in 5 minutes.')
    

@bot.event
async def on_command_error(ctx, error):
    if isinstance(error, commands.CommandNotFound):
        return
    raise error

bot.run(TOKEN)
