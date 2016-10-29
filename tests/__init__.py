import os

current_path = os.path.dirname(__file__)


def fixtures_path(name):
    return os.path.join(current_path, 'fixtures', name)