"""Shared fixtures for the Python 3 regression tests, without containers."""
import pytest

from native_network import Network, TANKS, TANKS_BASE, pmap


def pytest_addoption(parser):
    parser.addoption('--vmdebug', action='store_true',
                     help='pause the native topology for manual debugging before tests')


@pytest.fixture(scope='session')
def net(request):
    network = Network()
    try:
        if request.config.getoption('--vmdebug'):
            print('Namespaces are ready. Use ip netns exec <namespace> <command>.')
            input('Press Enter to run the tests: ')
        yield network
    finally:
        network.close()
