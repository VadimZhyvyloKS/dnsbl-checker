import shelve
import json

if __name__ == "__main__":
    with shelve.open('blacklisted', flag='r') as db:
        print(json.dumps(dict(db), indent=1, sort_keys=True))