import argparse
import json
import shelve

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
            data = db[args.ip_address]

        print(json.dumps(dict(data), indent=2, sort_keys=True))
