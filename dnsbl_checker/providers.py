""" 
Place to define providers.
Most part of _BASE_PROVIDERS was taken from https://github.com/vincecarney/dnsbl
"""

import requests
from bs4 import BeautifulSoup

from dnsbl_checker.utils import parse_file

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


def update_providers(fname, banned_providers=None):
    print("Getting list of black lists...")

    try:
        resp = requests.get("http://multirbl.valli.org/list/")
    except requests.exceptions.RequestException:
        print("Failed to fetch remote black lists. Continue...")
        return

    if resp.status_code != 200:
        print("Failed to fetch remote black lists. Continue...")
        return

    print("Received black lists")

    soup = BeautifulSoup(resp.content, 'html.parser')

    # rewrite providers
    with open(fname, 'w+') as file:
        for row in soup.find("table").find_all('tr'):
            if row.contents[6].next != 'b':  # provider is blacklist
                continue

            black_list = row.contents[2].next
            if (black_list == "(hidden)"
                    or black_list in banned_providers):
                continue

            file.write(black_list + '\n')


def get_providers(fname):
    providers = [ZenSpamhaus()]

    for host in parse_file(fname) or list():
        providers.append(Provider(host))

    return providers
