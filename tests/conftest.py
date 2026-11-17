"""Shared fixtures for every regression test, without containers."""
import os
from pathlib import Path

import pytest

from native_network import Network, TANKS, TANKS_BASE, pmap


def pytest_addoption(parser):
    parser.addoption('--vmdebug', action='store_true',
                     help='pause the native topology for manual debugging before tests')


def native_binary(variable, default):
    binary = Path(os.environ.get(variable, default)).resolve()
    if not binary.is_file():
        pytest.fail('Missing test executable %s; run tests/build first' % binary)
    return binary


@pytest.fixture(scope='session')
def redsocks_binary():
    return native_binary('REDSOCKS_BINARY', Path(__file__).resolve().parent.parent / 'redsocks')


@pytest.fixture(scope='session')
def net(request, redsocks_binary):
    prlimit = native_binary('REDSOCKS_PRLIMIT', Path(__file__).resolve().parent / 'prlimit-nofile')
    network = Network(redsocks_binary, prlimit)
    try:
        if request.config.getoption('--vmdebug'):
            print('Namespaces are ready. Use ip netns exec <namespace> <command>.')
            input('Press Enter to run the tests: ')
        yield network
    finally:
        network.close()
