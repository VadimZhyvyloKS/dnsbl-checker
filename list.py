import argparse
import json
import shelve
import sys

if __name__ == "__main__":
    arg_parser = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )
    arg_parser.add_argument(
        "ip_address", help="IP address (enter 'all' to list all addresses)"
    )

    args = arg_parser.parse_args()

    with shelve.open('blacklisted', flag='r') as db:
        if args.ip_address == 'all':
            data = db
        else:
            try:
                data = db[args.ip_address]
            except KeyError:
                print('IP {} was not found'.format(args.ip_address))
                sys.exit(1)

        print(json.dumps(dict(data), indent=2, sort_keys=True))
