import aiohttp
import discord

from discord import Webhook


class WebhookService:

    def __init__(self, webhook_url):
        self._webhook_url = webhook_url

    async def send(self, message):
        async with aiohttp.ClientSession() as _session:
            webhook = Webhook.from_url(self._webhook_url, session=_session)
            await webhook.send(message, username='Fuzzer')

    async def start(self):
        pass


class ReportService:

    def __init__(self, token, channel):
        self._token = token
        self._channel = channel
        self._client = None

    async def start(self):
        intents = discord.Intents.default()
        self._client = discord.Client(intents=intents)

        @self._client.event
        async def on_ready():
            print(f'Logged in as {self._client.user}')

        await self._client.start(self._token)

    async def send(self, message):
        # Wait until the bot is ready
        await self._client.wait_until_ready()

        # Find the channel by name
        for channel in self._client.get_all_channels():
            if isinstance(channel, discord.TextChannel) and channel.name == self._channel:
                # Send the message to the channel
                await channel.send(message)
                print("Message successfully sent to Discord!")
                return
