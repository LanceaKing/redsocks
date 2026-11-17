from functools import partial
from subprocess import CalledProcessError, Popen, PIPE
import time

import conftest
import pytest

GOOD_AUTH = 'connect_none connect_basic connect_digest socks5_none socks5_auth httperr_connect_digest'.split()
BAD_AUTH = 'connect_nopass connect_baduser connect_badpass socks5_nopass socks5_baduser socks5_badpass httperr_proxy_refuse'.split()
UGLY_AUTH = 'httperr_connect_nopass httperr_connect_baduser httperr_connect_badpass'.split()
assert set(conftest.TANKS) == set(GOOD_AUTH + BAD_AUTH + UGLY_AUTH + ['httperr_proxy_timeout'])

@pytest.mark.parametrize('tank', GOOD_AUTH)
def test_smoke(net, tank):
    vm = net.vm['tank%d' % conftest.TANKS[tank]]
    page = vm.do('curl --max-time 0.5 http://10.0.1.80/')
    assert 'Welcome to nginx!' in page

@pytest.mark.parametrize('tank', BAD_AUTH)
def test_badauth(net, tank):
    vm = net.vm['tank%d' % conftest.TANKS[tank]]
    with pytest.raises(CalledProcessError) as excinfo:
        vm.do('curl --max-time 0.5 http://10.0.1.80/')
    assert excinfo.value.returncode == 52 # Empty reply from server

@pytest.mark.parametrize('tank', UGLY_AUTH)
def test_uglyauth(net, tank):
    vm = net.vm['tank%d' % conftest.TANKS[tank]]
    page = vm.do('curl -sSv --max-time 0.5 http://10.0.1.80/')
    assert '<!-- ERR_CACHE_ACCESS_DENIED -->' in page

@pytest.mark.parametrize('tank', set(conftest.TANKS) - set(UGLY_AUTH + ['httperr_connect_digest']))
def test_econnrefused(net, tank):
    vm = net.vm['tank%d' % conftest.TANKS[tank]]
    with pytest.raises(CalledProcessError) as excinfo:
        vm.do('curl --max-time 0.5 http://10.0.1.80:81/')
    if tank == 'httperr_proxy_timeout':
        assert excinfo.value.returncode == 28 # Operation timed out
    else:
        assert excinfo.value.returncode == 52 # Empty reply from server

def test_econnrefused_httperr(net):
    tank = 'httperr_connect_digest'
    vm = net.vm['tank%d' % conftest.TANKS[tank]]
    page = vm.do('curl --max-time 0.5 http://10.0.1.80:81/')
    assert '<!-- ERR_CONNECT_FAIL -->' in page

RTT = 200 # ms

@pytest.fixture(scope="function")
def slow_net(request, net):
    def close():
        net.vm['gw'].netcall('tc qdisc del dev ethx root')
        net.vm['gw'].netcall('tc qdisc del dev ethw root')
    request.addfinalizer(close)
    net.vm['gw'].netcall('tc qdisc add dev ethw root netem delay %dms' % (RTT // 2))
    net.vm['gw'].netcall('tc qdisc add dev ethx root netem delay %dms' % (RTT // 2))
    return net

LATENCY = {
    'connect_none':     3 * RTT,
    'connect_basic':    3 * RTT,
    'connect_digest':   3 * RTT,
    'socks5_none':      4 * RTT,
    'socks5_auth':      5 * RTT,
    'regw_direct':      2 * RTT,
}

def heatup(vm):
    vm.do('curl -o /dev/null http://10.0.1.80/') # heatup L2 and auth caches

def http_ping(vm):
    s = vm.do('curl -sS -w %{time_connect}/%{time_total}/%{http_code}/%{size_download} -o /dev/null http://10.0.1.80/')
    connect, total, code, size = s.split('/')
    connect, total, code, size = float(connect) * 1000, float(total) * 1000, int(code), int(size)
    return connect, total, code, size

@pytest.mark.parametrize('tank', set(conftest.TANKS) & set(LATENCY))
def test_latency_tank(slow_net, tank):
    vm = slow_net.vm['tank%d' % conftest.TANKS[tank]]
    heatup(vm)
    connect, total, code, size = http_ping(vm)
    assert code == 200 and size == 612
    assert connect < 5 and LATENCY[tank]-RTT*.2 < total and total < LATENCY[tank]+RTT*.2

def test_latency_regw(slow_net):
    vm, tank = slow_net.vm['regw'], 'regw_direct'
    heatup(vm)
    connect, total, code, size = http_ping(vm)
    assert code == 200 and size == 612
    assert RTT*.8 < connect and connect < RTT*1.2 and LATENCY[tank]-RTT*.2 < total and total < LATENCY[tank]+RTT*.2

def test_nonce_reuse(slow_net):
    """ nonce reuse works and has no latency penalty """
    tank = 'connect_digest'
    vm = slow_net.vm['tank%d' % conftest.TANKS[tank]]
    heatup(vm)
    begin = time.time()
    s = conftest.pmap([partial(http_ping, vm) for _ in range(5)])
    total_sum = time.time() - begin
    for connect, total, code, size in s:
        assert code == 200 and size == 612
        assert connect < 5 and LATENCY[tank]-RTT*.2 < total and total < LATENCY[tank]+RTT*.2
        assert total_sum * 1000 < total * 1.5

@pytest.mark.parametrize('tank, delay', [(t, d)
    for t in set(conftest.TANKS) & set(LATENCY)
    for d in [_*0.001 for _ in range(1, LATENCY[t]+RTT, RTT//2)]
] + [
    ('httperr_proxy_refuse', (1 + 0*RTT/2) * 0.001),
    ('httperr_proxy_refuse', (1 + 1*RTT/2) * 0.001),
    ('httperr_proxy_refuse', (1 + 2*RTT/2) * 0.001),
    ('httperr_proxy_refuse', (1 + 3*RTT/2) * 0.001),
    ('httperr_proxy_timeout', (1 + 3*RTT/2) * 0.001),
])
def test_impatient_client(slow_net, tank, delay):
    vm, regw = slow_net.vm['tank%d' % conftest.TANKS[tank]], slow_net.vm['regw']
    before, start = regw.wait_idle(), time.time()
    try:
        page = vm.do('curl --max-time %s http://10.0.1.80/1M' % delay)
        #assert 'Welcome to nginx!' in page
    except CalledProcessError as e:
        if tank == 'httperr_proxy_refuse':
            assert e.returncode in (28, 52) # Operation timeout / Empty reply
        else:
            assert e.returncode == 28 # Operation timeout
    curl_time = time.time() - start
    assert curl_time < delay + RTT*0.001 # sanity check
    time.sleep( (LATENCY.get(tank, delay*1000) + 4*RTT)*0.001 )
    if tank == 'httperr_proxy_timeout':
        time.sleep(135) # default connect() timeout is long
    assert before == regw.wait_idle() # no leaks, including delayed FIN delivery

@pytest.fixture
def netcat(request):
    def start(command):
        process = Popen(command, stdin=PIPE, stdout=PIPE, text=True)

        def close():
            if process.poll() is None:
                process.kill()
            process.wait(timeout=5)
            process.stdin.close()
            process.stdout.close()

        request.addfinalizer(close)
        return process

    return start


@pytest.fixture(scope='function', params=range(80, 60, -1))
def lowfd_net(request, net):
    def close():
        net.vm['regw'].set_nofile(1024)
    request.addfinalizer(close)
    net.vm['regw'].set_nofile(request.param)
    return net

def test_accept_overflow(lowfd_net, netcat):
    tank = 'connect_none'
    vm, regw = lowfd_net.vm['tank%d' % conftest.TANKS[tank]], lowfd_net.vm['regw']
    lsfd = regw.wait_idle()
    year = str(time.gmtime().tm_year)
    discard_cmd = vm.exec_cmd('nc -q 0 10.0.1.13 discard')
    daytime_cmd = vm.exec_cmd('nc 10.0.1.13 daytime')

    dtstart = time.time()
    time.sleep(0.5)
    proc = [netcat(discard_cmd) for i in range(7)]
    # Server-first protocols use the one-second SNI deadline before opening
    # their upstream. Observe FD pressure only after those pumps are created.
    time.sleep(1.5)
    dt = netcat(daytime_cmd)
    time.sleep(1.5)
    logs = regw.logs(since=dtstart)
    if any(['Too many open files' in _[1] for _ in logs]):
        # anything may happen, except leaks
        proc[0].communicate('/dev/null\x0d\x0a', timeout=15)
        dt.communicate('', timeout=15)
        time.sleep(1)
        for p in proc[1:]:
            p.communicate('/dev/null\x0d\x0a', timeout=15)
    else:
        assert any(['reached redsocks_conn_max limit' in _[1] for _ in logs])
        # RLIMIT_NOFILE was not hit, this `daytime` call actually returns data
        daytime, _ = dt.communicate('', timeout=15)
        assert year in daytime and dt.returncode == 0
        time.sleep(0.5)
        dtdeath = time.time()
        proc.append(netcat(discard_cmd))
        time.sleep(1.5)
        logs = regw.logs(since=dtdeath)
        assert any(['reached redsocks_conn_max limit' in _[1] for _ in logs])
        time.sleep(0.5)
        dt = netcat(daytime_cmd)
        time.sleep(0.5)
        assert all([p.poll() is None for p in proc]) and dt.poll() is None # processes are running
        out, _ = proc[0].communicate('/dev/null\x0d\x0a', timeout=15)
        daytime, _ = dt.communicate('', timeout=15)
        assert year in daytime and dt.returncode == 0
        time.sleep(1)
        for p in proc[1:]:
            out, _ = p.communicate('/dev/null\x0d\x0a', timeout=15)
            assert out == ''

    time.sleep(1)
    assert lsfd == regw.wait_idle() # no leaks
