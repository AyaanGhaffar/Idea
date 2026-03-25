import discord
from discord.ext import commands
import asyncio
import os

class BotAccount:
    def __init__(self, token):
        self.token = token
        intents = discord.Intents.default()
        intents.message_content = True
        self.bot = commands.Bot(command_prefix='!', intents=intents)

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
        token = os.getenv('DISCORD_TOKEN', 'YOUR_TOKEN_HERE')
        bot_account = BotAccount(token)
        await bot_account.startup_phase()
        self.session_active = True
        await self.glory_session()

if __name__ == '__main__':
    monitor = GloryMonitor()
    asyncio.run(monitor.main())
