import asyncio
import os
from dotenv import load_dotenv

from fuzzerbot.service import ReportService
from fuzzerbot.watcher import Watcher, Consumer

load_dotenv()

DISCORD_TOKEN = os.getenv('DISCORD_TOKEN')
CHANNEL_NAME = os.getenv('CHANNEL_NAME') or "fuzzer"
WATCH_DIRECTORY = os.getenv('WATCH_DIRECTORY') or "output/hydration-runtime-fuzzer/crashes"

if DISCORD_TOKEN is None:
    print("Error: Missing DISCORD_TOKEN environment variable")
    exit(1)

print(f"Running fuzzerbot. Channel {CHANNEL_NAME}. Watching {WATCH_DIRECTORY}")

loop = asyncio.get_event_loop()
queue = asyncio.Queue()

watcher = Watcher(WATCH_DIRECTORY, loop, queue)
service = ReportService(DISCORD_TOKEN, CHANNEL_NAME)
consumer = Consumer(service, queue)

futures = [
    service.start(),
    loop.run_in_executor(None, watcher.start),
    consumer.consume(),
]

loop.run_until_complete(asyncio.gather(*futures))

print("Bye.")
