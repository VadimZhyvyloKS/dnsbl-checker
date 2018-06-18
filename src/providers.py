""" 
Place to define providers.
Most part of _BASE_PROVIDERS was taken from https://github.com/vincecarney/dnsbl
"""

import requests
from bs4 import BeautifulSoup

# providers answers could be interpreted in one of the following categories
DNSBL_CATEGORIES = {'spam', 'proxy', 'malware', 'botnet', 'exploits', 'unknown'}


class Provider(object):

    def __init__(self, host):
        self.host = host

    def process_response(self, response):
        result = set()
        if response:
            return {'unknown'}
        return result

    def __repr__(self):
        return "<Provider: %s>" % self.host


class ZenSpamhaus(Provider):
    """ Combined spamhaus list:
        https://www.spamhaus.org/faq/section/DNSBL%20Usage#200
    """

    def __init__(self, host='zen.spamhaus.org'):
        Provider.__init__(self, host=host)

    def process_response(self, response):
        categories = set()
        for result in response:
            if result.host in ['127.0.0.2', '127.0.0.3', '127.0.0.9']:
                categories.add('spam')
            if result.host in ['127.0.0.4', '127.0.0.5', '127.0.0.6',
                               '127.0.0.7']:
                categories.add('exploits')
        return categories


# this list is converted into list of Providers bellow
_BASE_PROVIDERS = [
    'aspews.ext.sorbs.net',
    'b.barracudacentral.org',
    'bl.deadbeef.com',
    'bl.spamcop.net',
    'blackholes.five-ten-sg.com',
    'blacklist.woody.ch',
    'bogons.cymru.com',
    'cbl.abuseat.org',
    'cdl.anti-spam.org.cn',
    'combined.abuse.ch',
    'combined.rbl.msrbl.net',
    'db.wpbl.info',
    'dnsbl-1.uceprotect.net',
    'dnsbl-2.uceprotect.net',
    'dnsbl-3.uceprotect.net',
    'dnsbl.cyberlogic.net',
    'dnsbl.inps.de',
    'dnsbl.sorbs.net',
    'drone.abuse.ch',
    'dul.dnsbl.sorbs.net',
    'dul.ru',
    'dyna.spamrats.com',
    'dynip.rothen.com',
    'http.dnsbl.sorbs.net'
    'images.rbl.msrbl.net',
    'ips.backscatterer.org',
    'ix.dnsbl.manitu.net',
    'korea.services.net',
    'misc.dnsbl.sorbs.net',
    'noptr.spamrats.com',
    'phishing.rbl.msrbl.net',
    'proxy.bl.gweep.ca',
    'proxy.block.transip.nl',
    'psbl.surriel.com',
    'rbl.interserver.net',
    'relays.bl.gweep.ca',
    'relays.bl.kundenserver.de',
    'relays.nether.net',
    'residential.block.transip.nl',
    'smtp.dnsbl.sorbs.net',
    'socks.dnsbl.sorbs.net',
    'spam.abuse.ch',
    'spam.dnsbl.sorbs.net',
    'spam.rbl.msrbl.net',
    'spam.spamrats.com',
    'spamlist.or.kr',
    'spamrbl.imp.ch',
    'tor.dnsbl.sectoor.de',
    'torserver.tor.dnsbl.sectoor.de',
    'ubl.lashback.com',
    'ubl.unsubscore.com',
    'virbl.bit.nl',
    'virus.rbl.msrbl.net',
    'web.dnsbl.sorbs.net',
    'wormrbl.imp.ch',
    'zombie.dnsbl.sorbs.net',
]

_BANNED_BLACKLISTS = (
    "dwl.dnswl.org",
    "list.dnswl.org"
)


def retrieve_remote_providers():
    providers = list()

    print("Getting list of black lists")
    resp = requests.get("http://multirbl.valli.org/list/")

    if resp.status_code != 200:
        print("Error during fetching remote black lists")
    else:
        print("Received black lists")
        
        soup = BeautifulSoup(resp.content, 'html.parser')

        for x in soup.find("table").find_all('tr'):
            black_list = x.contents[2].next
            if (black_list == "(hidden)"
                    or black_list in _BANNED_BLACKLISTS
                    or black_list in _BASE_PROVIDERS):
                continue

            providers.append(Provider(black_list))

    return providers


BASE_PROVIDERS = [Provider(host) for host in _BASE_PROVIDERS] + [ZenSpamhaus()]
