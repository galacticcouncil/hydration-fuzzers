import asyncio
import os
from dotenv import load_dotenv

from fuzzerbot.service import ReportService, WebhookService
from fuzzerbot.watcher import Watcher, Consumer

load_dotenv()

DISCORD_TOKEN = os.getenv('DISCORD_TOKEN')
WEBHOOK_URL= os.getenv('WEBHOOK_URL')
CHANNEL_NAME = os.getenv('CHANNEL_NAME') or "fuzzer"
WATCH_DIRECTORY = os.getenv('WATCH_DIRECTORY') or "output/hydration-runtime-fuzzer/crashes"

if DISCORD_TOKEN is None and WEBHOOK_URL is None:
    print("Error: Missing DISCORD_TOKEN or WEBHOOK_URL environment variable")
    exit(1)

loop = asyncio.get_event_loop()
queue = asyncio.Queue()

watcher = Watcher(WATCH_DIRECTORY, loop, queue)

# One or the other. If both are specified, webhook has precedence
if DISCORD_TOKEN is not None:
    service = ReportService(DISCORD_TOKEN, CHANNEL_NAME)
if WEBHOOK_URL is not None:
    service = WebhookService(WEBHOOK_URL)

consumer = Consumer(service, queue)

futures = [
    service.start(),
    loop.run_in_executor(None, watcher.start),
    consumer.consume(),
]

loop.run_until_complete(asyncio.gather(*futures))

print("Bye.")
