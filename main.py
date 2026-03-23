import discord
from discord.ext import commands
import asyncio

class BotAccount:
    def __init__(self, token):
        self.token = token
        self.bot = commands.Bot(command_prefix='!')

    async def startup_phase(self):
        @self.bot.event
        async def on_ready():
            print(f'Bot is ready. Logged in as {self.bot.user}')

        await self.bot.start(self.token)

class GloryMonitor:
    def __init__(self):
        self.session_active = False

    async def glory_session(self):
        while self.session_active:
            # Main logic of the glory session goes here
            print('Glory session running...')
            await asyncio.sleep(10)

    async def main(self):
        bot_account = BotAccount('YOUR_TOKEN_HERE')
        await bot_account.startup_phase()
        self.session_active = True
        await self.glory_session()
