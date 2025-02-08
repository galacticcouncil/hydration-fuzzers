import asyncio
import time
from typing import Optional

from watchdog.events import FileSystemEventHandler
from watchdog.observers import Observer

from fuzzerbot.process import process_crash_report
from fuzzerbot.service import ReportService


class EventHandler(FileSystemEventHandler):

    def __init__(self, loop: asyncio.AbstractEventLoop, queue: asyncio.Queue):
        self._queue = queue
        self._loop = loop

    def on_created(self, event):
        if event.is_directory:
            print(f"New directory created: {event.src_path}")
        else:
            print(f"New file created: {event.src_path}")
            self._loop.call_soon_threadsafe(self._queue.put_nowait, event.src_path)


class Watcher:
    def __init__(self, directory, loop: asyncio.AbstractEventLoop, queue: asyncio.Queue):
        self._directory = directory
        self._handler = EventHandler(loop, queue)
        self._observer = None

    def start(self):
        self._observer = Observer()
        self._observer.schedule(self._handler, self._directory, recursive=True)  # Watch the directory recursively
        self._observer.start()

        print(f"Started watching {self._directory} for new files and directories...")

        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            self._observer.stop()
            print("Stopped watching.")
        self._observer.join(10)


class EventIterator(object):
    def __init__(self, queue: asyncio.Queue,
                 loop: Optional[asyncio.BaseEventLoop] = None):
        self.queue = queue

    def __aiter__(self):
        return self

    async def __anext__(self):
        item = await self.queue.get()

        if item is None:
            raise StopAsyncIteration

        return item


class Consumer:
    def __init__(self, client: ReportService, queue: asyncio.Queue):
        self._client = client
        self._queue = queue

    async def consume(self):
        async for event in EventIterator(self._queue):
            msg = process_crash_report(event)
            await self._client.send(msg)
