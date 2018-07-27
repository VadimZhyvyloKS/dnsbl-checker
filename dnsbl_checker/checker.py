import socket
import asyncio
import aiodns

from dnsbl_checker.providers import DNSBL_CATEGORIES


class DNSBLResult(object):
    """
    DNSBL Result class to keep all info about ip request results.

    """
    def __init__(self, addr=None, results=None):
        self.addr = addr
        self._results = results
        self.blacklisted = False
        self.providers = []
        self.failed_providers = []
        self.detected_by = {}
        self.categories = set()
        self.process_results()

    def process_results(self):
        """ Process results by providers """
        for result in self._results:
            provider = result.provider
            self.providers.append(provider)
            if result.error:
                self.failed_providers.append(provider.host)
                continue

            if not result.response['a_response']:
                continue

            # set blacklisted to True if ip is detected with at least one dnsbl
            self.blacklisted = True

            provider_categories = provider.process_response(
                result.response['a_response']
            )
            assert provider_categories.issubset(DNSBL_CATEGORIES)
            self.categories = self.categories.union(provider_categories)

            txt_response = result.response['txt_response']

            self.detected_by[str(provider.host)] = dict(
                result=dict(
                    a_response=result.response['a_response'][0].host,
                    txt_response=(txt_response[0].text.decode('utf-8')
                                  if txt_response else "TXT request failed")
                ),
                catogories=list(provider_categories)
            )

    def __repr__(self):
        blacklisted = '[BLACKLISTED]' if self.blacklisted else ''
        return "<DNSBLResult: %s %s (%d/%d)>" % (self.addr, blacklisted,
                                                 len(self.detected_by),
                                                 len(self.providers))


class DNSBLResponse(object):
    """
    DNSBL Response object
    """
    def __init__(self, addr=None, provider=None, response=None, error=None):
        self.addr = addr
        self.provider = provider
        self.response = response
        self.error = error


class DNSBLChecker(object):
    def __init__(self,
                 providers,
                 timeout=5,
                 tries=2,
                 concurrency=200,
                 loop=None):

        self.providers = providers

        self.progress = None

        self._loop = loop or asyncio.get_event_loop()
        self._resolver = aiodns.DNSResolver(
            timeout=timeout,
            tries=tries,
            loop=self._loop
        )
        self._semaphore = asyncio.Semaphore(concurrency, loop=self._loop)

    async def dnsbl_request(self, addr, provider):
        """
        Make lookup to dnsbl provider
        Parameters:
            * addr (string) - ip address to check
            * provider (string) - dnsbl provider

        Returns:
            * DNSBLResponse object

        Raises:
            * ValueError
        """
        ip_reversed = '.'.join(reversed(addr.split('.')))
        dnsbl_query = "%s.%s" % (ip_reversed, provider.host)

        a_response = None
        txt_response = None
        error = None

        async with self._semaphore:
            try:
                a_response = await self._resolver.query(dnsbl_query, 'A')
            except aiodns.error.DNSError as exc:
                if exc.args[0] != 4:  # 4: domain name not found:
                    error = exc
            else:
                try:
                    txt_response = await self._resolver.query(
                        dnsbl_query, 'TXT'
                    )
                except aiodns.error.DNSError:
                    pass

        if self.progress is not None:
            self.progress.update(1)

        return DNSBLResponse(
            addr=addr,
            provider=provider,
            response=dict(a_response=a_response, txt_response=txt_response),
            error=error
        )

    async def _check_ip(self, addr):
        try:
            socket.inet_aton(addr)
        except socket.error:
            raise ValueError('wrong ip format')

        tasks = []
        for provider in self.providers:
            tasks.append(self.dnsbl_request(addr, provider))
        results = await asyncio.gather(*tasks)

        return DNSBLResult(addr=addr, results=results)

    def check_ips(self, addrs):
        tasks = []
        for addr in addrs:
            tasks.append(self._check_ip(addr))
        return self._loop.run_until_complete(asyncio.gather(*tasks))
