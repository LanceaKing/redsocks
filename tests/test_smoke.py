from functools import partial
from contextlib import ExitStack
from subprocess import CalledProcessError, Popen, PIPE
from statistics import median
import json
import shlex
import time

import conftest
import pytest

GOOD_AUTH = 'connect_none connect_basic connect_digest socks5_none socks5_auth httperr_connect_digest'.split()
BAD_AUTH = 'connect_nopass connect_baduser connect_badpass socks5_nopass socks5_baduser socks5_badpass httperr_proxy_refuse'.split()
UGLY_AUTH = 'httperr_connect_nopass httperr_connect_baduser httperr_connect_badpass'.split()
assert set(conftest.TANKS) == set(GOOD_AUTH + BAD_AUTH + UGLY_AUTH + ['httperr_proxy_timeout'])

def rejected_http_request(vm, port, record_testsuite_property):
    started = time.monotonic()
    with pytest.raises(CalledProcessError) as excinfo:
        vm.do(r'curl -sS --max-time 0.5 --output /dev/null '
              r'--write-out "\n%{http_code} %{size_download}" '
              f'http://10.0.1.80:{port}/')
    error = excinfo.value
    status, size = error.output.rsplit('\n', 1)[1].split()
    record_testsuite_property('http.rejection.%s.%d' % (vm.name, port), json.dumps({
        'curl_code': error.returncode, 'http_code': int(status), 'body_bytes': int(size),
        'elapsed_ms': (time.monotonic()-started)*1000, 'diagnostic': error.output}))
    assert status == '000' and int(size) == 0, error.output
    return error

def assert_empty_reply(error):
    # A proxy can reject before the HTTP request is fully consumed. Depending
    # on packet ordering, TCP closes with FIN (curl 52) or peer RST (curl 56).
    # Only the explicit peer-reset diagnostic qualifies; HTTP status and body
    # must already be zero. Timeouts and other receive failures still fail.
    assert error.returncode == 52 or (error.returncode == 56 and
        'Recv failure: Connection reset by peer' in error.output), error.output

@pytest.mark.parametrize('tank', GOOD_AUTH)
def test_smoke(net, tank):
    vm = net.vm['tank%d' % conftest.TANKS[tank]]
    page = vm.do('curl --max-time 0.5 http://10.0.1.80/')
    assert 'Welcome to nginx!' in page

@pytest.mark.parametrize('tank', BAD_AUTH)
def test_badauth(net, tank, record_testsuite_property):
    vm = net.vm['tank%d' % conftest.TANKS[tank]]
    assert_empty_reply(rejected_http_request(vm, 80, record_testsuite_property))
    net.vm['regw'].wait_idle()

@pytest.mark.parametrize('tank', UGLY_AUTH)
def test_uglyauth(net, tank):
    vm = net.vm['tank%d' % conftest.TANKS[tank]]
    page = vm.do('curl -sSv --max-time 0.5 http://10.0.1.80/')
    assert '<!-- ERR_CACHE_ACCESS_DENIED -->' in page

@pytest.mark.parametrize('tank', set(conftest.TANKS) - set(UGLY_AUTH + ['httperr_connect_digest']))
def test_econnrefused(net, tank, record_testsuite_property):
    vm = net.vm['tank%d' % conftest.TANKS[tank]]
    error = rejected_http_request(vm, 81, record_testsuite_property)
    if tank == 'httperr_proxy_timeout':
        assert error.returncode == 28 # Operation timed out
        # The client's deadline does not end the kernel's pending upstream
        # connect(). Drain it before later tests record their FD baseline.
        net.vm['regw'].wait_idle(timeout=145)
    else:
        assert_empty_reply(error)
        net.vm['regw'].wait_idle()

def test_econnrefused_httperr(net):
    tank = 'httperr_connect_digest'
    vm = net.vm['tank%d' % conftest.TANKS[tank]]
    page = vm.do('curl --max-time 0.5 http://10.0.1.80:81/')
    assert '<!-- ERR_CONNECT_FAIL -->' in page

RTT = 200 # ms

def add_latency(request, net):
    def close():
        # Deleting netem with pending FINs drops them and leaves connections
        # occupying the fixture's eight slots until TCP retransmits them.
        with ExitStack() as cleanup:
            cleanup.callback(net.stop_timing_pulses)
            cleanup.callback(net.vm['gw'].netcall, 'tc qdisc del dev ethw root')
            cleanup.callback(net.vm['gw'].netcall, 'tc qdisc del dev ethx root')
            net.vm['regw'].wait_idle()
    net.vm['regw'].wait_idle()
    net.start_timing_pulses()
    request.addfinalizer(close)
    net.vm['gw'].netcall('tc qdisc add dev ethw root netem delay %dms' % (RTT // 2))
    net.vm['gw'].netcall('tc qdisc add dev ethx root netem delay %dms' % (RTT // 2))
    return net

@pytest.fixture(scope="function")
def slow_net(request, net):
    return add_latency(request, net)

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

def http_ping(vm, proxy_args=()):
    s = vm.do(shlex.join([
        'curl', '-sS', *proxy_args,
        '-w', '%{time_connect}/%{time_total}/%{http_code}/%{size_download}/%{http_connect}/%{num_connects}',
        '-o', '/dev/null', 'http://10.0.1.80/']))
    connect, total, code, size, tunnel, connections = s.split('/')
    assert int(connections) == 1
    assert int(tunnel) == (200 if '--proxytunnel' in proxy_args else 0)
    connect, total, code, size = float(connect) * 1000, float(total) * 1000, int(code), int(size)
    return connect, total, code, size

def reference_ping(net, tank):
    # Use stock curl and the same upstream process, without passing through
    # redsocks. Each command has the same wire RTT count as the tested path.
    # Cached Digest needs one CONNECT, so its reference uses Squid's open port;
    # a fresh curl Digest challenge would add an unrelated round trip.
    proxies = {
        'connect_none': ('--proxy', 'http://10.0.1.8:8080', '--proxytunnel'),
        'connect_basic': ('--proxy', 'http://10.0.1.8:8081', '--proxytunnel',
                          '--proxy-basic', '--proxy-user', 'basic_user:basic_password'),
        'connect_digest': ('--proxy', 'http://10.0.1.9:8080', '--proxytunnel'),
        'socks5_none': ('--socks5', '10.0.1.180:1080'),
        'socks5_auth': ('--socks5', '10.0.1.181:1081', '--socks5-basic',
                       '--proxy-user', net.account + ':sockpwd'),
    }
    # VM.do deliberately disables environment proxies for ordinary clients.
    return http_ping(net.vm['regw'], ('--noproxy', '', *proxies[tank]))

def paired_samples(net, tank, concurrency):
    vm = net.vm['tank%d' % conftest.TANKS[tank]]
    net.vm['regw'].wait_idle()
    calls = [function for _ in range(concurrency) for function in (
        partial(reference_ping, net, tank), partial(http_ping, vm))]
    begin = time.monotonic()
    values = conftest.pmap(calls)
    elapsed = time.monotonic() - begin
    controls, samples = values[0::2], values[1::2]
    assert all(code == 200 and size == 612 for _, _, code, size in values)
    return controls, samples, elapsed

@pytest.fixture
def timed_net(request, net, record_testsuite_property):
    concurrency = getattr(request, 'param', 1)

    def measure_direct(label):
        vm = net.vm['regw']
        heatup(vm)
        values = []
        for _ in range(3):
            net.vm['regw'].wait_idle()
            values.extend(conftest.pmap([partial(http_ping, vm) for _ in range(concurrency)]))
        total = median(total for _, total, _, _ in values)
        # Record the complete calibration before either assertion can fail.
        record_testsuite_property('timing.direct.'+label+'.'+request.node.name,
                                 json.dumps({'concurrency': concurrency,
                                             'samples_ms': values, 'median_ms': total}))
        assert all(code == 200 and size == 612 for _, _, code, size in values)
        return total

    direct_baseline = measure_direct('baseline')
    baseline = {}
    for tank in set(conftest.TANKS) & set(LATENCY):
        heatup(net.vm['tank%d' % conftest.TANKS[tank]])
        controls, samples = [], []
        for _ in range(3):
            control, sample, _ = paired_samples(net, tank, concurrency)
            controls.extend(control)
            samples.extend(sample)
        baseline[tank] = {
            'reference_ms': median(total for _, total, _, _ in controls),
            'proxy_ms': median(total for _, total, _, _ in samples),
        }
    add_latency(request, net)
    control = measure_direct('control')
    record_testsuite_property('timing.'+request.node.name, json.dumps({
        'concurrency': concurrency, 'baseline_ms': baseline, 'timing_cpus': net.cpus,
        'direct_baseline_ms': direct_baseline, 'direct_control_ms': control}))
    assert LATENCY['regw_direct']-RTT*.2 < control < LATENCY['regw_direct']+RTT*.2
    return net, baseline

def paired_pings(net, baseline, tank, concurrency):
    vm = net.vm['tank%d' % conftest.TANKS[tank]]
    heatup(vm)
    controls, samples, elapsed = paired_samples(net, tank, concurrency)
    assert all(code == 200 and size == 612 and RTT*.8 < connect < RTT*1.2
               for connect, _, code, size in controls)
    assert all(total > LATENCY[tank]-RTT*.2 for _, total, _, _ in controls)
    service = baseline[tank]
    expected = median(total for _, total, _, _ in controls) + service['proxy_ms'] - service['reference_ms']
    return expected, samples, controls, elapsed

@pytest.mark.parametrize('tank', set(conftest.TANKS) & set(LATENCY))
def test_latency_tank(timed_net, tank, record_testsuite_property):
    net, baseline = timed_net
    expected, samples, controls, _ = paired_pings(net, baseline, tank, 1)
    record_testsuite_property('timing.pair.'+tank, json.dumps({'expected_ms': expected, 'control': controls, 'samples': samples}))
    (connect, total, code, size), = samples
    assert code == 200 and size == 612
    assert connect < 5 and expected-RTT*.2 < total and total < expected+RTT*.2

def test_latency_regw(slow_net, record_testsuite_property):
    vm, tank = slow_net.vm['regw'], 'regw_direct'
    heatup(vm)
    connect, total, code, size = http_ping(vm)
    record_testsuite_property('timing.direct.regw', json.dumps({
        'sample_ms': (connect, total, code, size), 'timing_cpus': slow_net.cpus}))
    assert code == 200 and size == 612
    assert RTT*.8 < connect and connect < RTT*1.2 and LATENCY[tank]-RTT*.2 < total and total < LATENCY[tank]+RTT*.2

@pytest.mark.parametrize('timed_net', [5], indirect=True)
def test_nonce_reuse(timed_net, record_testsuite_property):
    """ nonce reuse works and has no latency penalty """
    tank = 'connect_digest'
    net, baseline = timed_net
    expected, s, controls, total_sum = paired_pings(net, baseline, tank, 5)
    record_testsuite_property('timing.pair.nonce', json.dumps({'expected_ms': expected, 'control': controls, 'samples': s}))
    for connect, total, code, size in s:
        assert code == 200 and size == 612
        assert connect < 5 and expected-RTT*.2 < total and total < expected+RTT*.2
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
        regw.wait_idle(timeout=145) # default connect() timeout is long
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
