import copy


class Ip:
    def __init__(self, db, addr):
        self.db = db
        self.addr = addr

        self.blacklists = self.db.get(addr, dict())

    def save(self):
        self.db[self.addr] = self.blacklists


class Saver:
    def __init__(self, db):
        self._db = db

        self.changes = {}

    def save_results(self, results):
        for result in results:
            ip = Ip(self._db, result.addr)

            change_data = dict()

            new_blacklists = set(result.detected_by) - set(ip.blacklists)
            for bl in new_blacklists:
                data = {bl: result.detected_by[bl]}
                change_data.setdefault('added_bls', dict()).update(data)

                ip.blacklists.update(data)

            blacklists_to_delete = set(ip.blacklists) - set(result.detected_by)
            for bl in blacklists_to_delete:
                if bl in result.failed_providers:
                    continue

                change_data.setdefault('deleted_bls', dict()).update({
                    bl: copy.deepcopy(ip.blacklists[bl])
                })

                del ip.blacklists[bl]

            if change_data:
                self.changes[ip.addr] = change_data

            ip.save()

    def delete_providers(self, providers):
        for provider in providers:
            for ip, bls in self._db.items():
                if provider in bls:
                    del self._db[ip][provider]
                    break
