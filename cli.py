import asyncio
import json
import shelve
import sys
import os

import click
import yaml
import tqdm

from src.utils import parse_file
from src.providers import update_providers, get_providers
from src.checker import DNSBLChecker
from src.saver import Saver
from src.telegram import TGClient

dir_path = os.path.dirname(os.path.realpath(__file__))

db_file = dir_path + '/blacklisted'
providers_file = dir_path + '/providers.txt'


@click.group()
def cli():
    pass


@cli.command()
@click.argument('ip_addr')
def get(ip_addr):
    with shelve.open(db_file, flag='r') as db:
        if ip_addr == 'all':
            data = db
        else:
            try:
                data = db[ip_addr]
            except KeyError:
                print('IP {} was not found'.format(ip_addr))
                sys.exit(1)

        print(json.dumps(dict(data), indent=2, sort_keys=True))


@cli.command()
@click.argument('conf_file', type=click.File(mode='r'))
def check(conf_file):
    config = yaml.load(conf_file)

    if 'ips' not in config:
        print('"ips" param is required')

    loop = asyncio.get_event_loop()

    result = inspect(
        parse_file(config['ips']),
        loop,
        parse_file(config.get('banned_providers'))
    )

    with shelve.open(db_file) as db:
        saver = Saver(db)
        saver.save_results(result)

    if 'telegram_token' in config and 'telegram_ids' in config:
        print('Sending notifications...')

        notify(config['telegram_token'],
               config['telegram_ids'],
               loop,
               saver.changes)

        print('Notifications were sent')
    else:
        print('Skipping notifications')


def inspect(ips, loop, banned_providers=None):
    update_providers(providers_file,
                     banned_providers=banned_providers)

    checker = DNSBLChecker(get_providers(providers_file),
                           loop=loop,
                           concurrency=300)

    with tqdm.tqdm(total=len(ips) * len(checker.providers),
                   miniters=1,
                   smoothing=0,
                   desc="IP checks",
                   unit=" requests") as checker.progress:
        return checker.check_ips(ips)


def notify(bot_token, chat_ids, loop, data=None):
    tg_client = TGClient(
        bot_token,
        chat_ids,
        loop=loop
    )

    if data:
        msgs = prepare_tg_msgs(data)
        tg_client.send_msgs(*msgs)
    else:
        tg_client.send_msgs('Changes were not found')


def prepare_tg_msgs(changes):
    msgs = list()

    def get_record(bl, data):
        resp = data['result']

        return (
            '*{host}*: {a_addr}\nTXT response: {txt}'.format(
                host=bl,
                a_addr=resp['a_response'],
                txt=resp['txt_response']
            )
        )

    for ip, change in changes.items():

        if change.get('added_bls'):
            msg = '{}\nFound in:\n{}'
            for bl, data in change['added_bls'].items():
                msgs.append(msg.format(ip, get_record(bl, data)))

        if change.get('deleted_bls'):
            msg = '{}\nDeleted from:\n{}'
            for bl, data in change['deleted_bls'].items():
                msgs.append(msg.format(ip, get_record(bl, data)))

    return msgs
