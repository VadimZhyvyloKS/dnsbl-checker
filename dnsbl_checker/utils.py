import os


def parse_file(file):
    if file is None or not os.path.isfile(file):
        return list()

    items = list()
    with open(file, "rt") as list_file:
        for line in list_file:
            item = line.split('#', 1)[0].rstrip()
            if item:
                items.append(item)
    return items
