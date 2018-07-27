import asyncio

import aiohttp


class TGClient:
    def __init__(self, token, chat_ids, loop=None):
        self.url = 'https://api.telegram.org/bot{}/sendMessage'.format(token)
        self.chat_ids = chat_ids

        self._loop = loop or asyncio.get_event_loop()
        self._session = lambda: aiohttp.ClientSession(loop=self._loop)
        self._semaphore = asyncio.Semaphore(5, loop=self._loop)

    async def _send_request(self, client, data):
        async with self._semaphore:
            async with client.post(self.url, data=data) as response:
                return await response.text()

    async def _send_msg(self, msg, client):
        tasks = []
        for chat_id in self.chat_ids:
            data = dict(
                chat_id=chat_id,
                text=msg,
                parse_mode='Markdown',
                disable_web_page_preview=True
            )

            tasks.append(self._send_request(client, data))

        return await asyncio.gather(*tasks)

    async def async_send_msgs(self, msgs):
        tasks = []
        async with self._session() as client:
            for msg in msgs:
                tasks.append(self._send_msg(msg, client))

            return await asyncio.gather(*tasks)

    def send_msgs(self, *msgs):
        return self._loop.run_until_complete(self.async_send_msgs(msgs))
