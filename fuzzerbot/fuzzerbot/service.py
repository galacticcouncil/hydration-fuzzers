import discord


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
