import asyncio
import aiohttp

# Assuming you have some existing structure for your async methods

async def get_clan_info(clan_id):
    async with aiohttp.ClientSession() as session:
        async with session.get(f'GetClanInfoByClanId/{clan_id}') as response:
            return await response.json()

async def request_guild_join(guild_id):
    # Existing join logic
    pass

async def _heartbeat_loop():
    while True:
        try:
            # Your existing code that could fail
            pass
        except ConnectionError:
            print('Connection lost. Attempting to reconnect...')
            await asyncio.sleep(5)  # Wait before reconnecting

async def startup_phase(guild_id):
    clan_id = extract_clan_id(guild_id)  # Update this method to retrieve clan_id from guild_id
    clan_info = await get_clan_info(clan_id)
    if clan_info:
        await request_guild_join(guild_id)
    else:
        print('Guild does not exist.')