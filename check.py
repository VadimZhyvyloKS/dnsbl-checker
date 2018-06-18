import argparse
import asyncio
import shelve

import tqdm

from src.checker import DNSBLChecker
from src.telegram import TGClient
from src.saver import Saver


def parse_ips(file):
    ips = list()
    with open(file, "rt") as list_file:
        for line in list_file:
            ip = line.split('#', 1)[0].rstrip()
            if ip:
                ips.append(ip)
    return ips


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


if __name__ == "__main__":
    arg_parser = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )
    arg_parser.add_argument(
        "list_file", help="IP list file path"
    )
    arg_parser.add_argument(
        '-t', '--bot-token', help='Telegram bot token', required=True
    )
    arg_parser.add_argument(
        '-i', '--chat-ids', nargs='+',
        help='List of telegram chat ids', required=True
    )

    args = arg_parser.parse_args()

    loop = asyncio.get_event_loop()

    tg_client = TGClient(
        token=args.bot_token,
        chat_ids=args.chat_ids,
        loop=loop
    )

    try:
        ips = parse_ips(args.list_file)

        checker = DNSBLChecker(loop=loop, concurrency=300)
        with tqdm.tqdm(total=len(ips) * len(checker.providers),
                       miniters=1,
                       smoothing=0,
                       desc="IP checks",
                       unit=" requests") as checker.progress:
            result = checker.check_ips(ips)

        with shelve.open('blacklisted') as db:
            saver = Saver(db)
            saver.save_results(result)

        if saver.changes:
            msgs = prepare_tg_msgs(saver.changes)
            tg_client.send_msgs(*msgs)
        else:
            tg_client.send_msg('Changes were not found')

    except Exception as e:
        tg_client.send_msg(
            'Error during run of dnsbl checker:\n{}'.format(str(e))
        )
        raise

