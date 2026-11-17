"""Run the upstream topology in native Linux network namespaces, without Docker.

Bridges, forwarding and firewall changes are confined to task-owned namespaces.
Services use temporary files and a temporary account for Dante authentication.
"""
from concurrent.futures import ThreadPoolExecutor
import os
from pathlib import Path
import re
import shlex
import shutil
import signal
import subprocess
import tempfile
import time


ROOT = Path(__file__).resolve().parent
TANKS_BASE = 10
TANKS = {name: TANKS_BASE + i for i, name in enumerate([
    'connect_none', 'connect_basic', 'connect_digest', 'socks5_none',
    'socks5_auth', 'connect_nopass', 'connect_baduser', 'connect_badpass',
    'socks5_nopass', 'socks5_baduser', 'socks5_badpass',
    'httperr_connect_nopass', 'httperr_connect_baduser',
    'httperr_connect_badpass', 'httperr_connect_digest',
    'httperr_proxy_refuse', 'httperr_proxy_timeout',
])}


def pmap(functions):
    with ThreadPoolExecutor(max_workers=len(functions)) as pool:
        return list(pool.map(lambda function: function(), functions))


def run(command, **kwargs):
    return subprocess.check_output(command, text=True, stderr=subprocess.STDOUT, **kwargs)


class VM:
    def __init__(self, network, name):
        self.network = network
        self.name = name
        self.namespace = network.prefix + '-' + name
        self.process = None
        self.logpath = network.work / (name + '.log')
        network.vm[name] = self
        run(['ip', 'netns', 'add', self.namespace])
        network.namespaces.append(self.namespace)
        self.netcall('ip link set lo up')

    @property
    def pid(self):
        return self.process.pid

    def exec_cmd(self, command):
        return ['ip', 'netns', 'exec', self.namespace, *shlex.split(command)]

    def do(self, command):
        env = dict(os.environ, NO_PROXY='*', no_proxy='*')
        return run(self.exec_cmd(command), env=env)

    def netcall(self, command):
        return run(self.exec_cmd(command))

    def connect(self, subnet, address, interface, gateway=None):
        self.network.link_index += 1
        host = 'h%d' % self.network.link_index
        peer = 'p%d' % self.network.link_index
        fabric = self.network.fabric
        run(['ip', '-n', fabric, 'link', 'add', host, 'type', 'veth', 'peer', 'name', peer])
        run(['ip', '-n', fabric, 'link', 'set', peer, 'netns', self.namespace])
        run(['ip', '-n', fabric, 'link', 'set', host, 'master', 'br-' + subnet])
        run(['ip', '-n', fabric, 'link', 'set', host, 'up'])
        self.netcall('ip link set %s name %s' % (peer, interface))
        self.netcall('ip addr add %s/24 dev %s' % (address, interface))
        self.netcall('ip link set %s up' % interface)
        if gateway:
            self.netcall('ip route replace default via %s' % gateway)

    def start(self, command, ports):
        self.logfile = self.logpath.open('w')
        self.process = subprocess.Popen(self.exec_cmd(command), stdout=self.logfile,
                                        stderr=subprocess.STDOUT, start_new_session=True)
        deadline = time.monotonic() + 15
        while time.monotonic() < deadline:
            if self.process.poll() is not None:
                break
            listeners = self.netcall('ss -ltnH')
            if all(re.search(r':%d\s' % port, listeners) for port in ports):
                return
            time.sleep(.05)
        raise RuntimeError('%s failed to listen:\n%s' % (self.name, self.logpath.read_text()))

    def lsfd(self):
        return sorted(int(path.name) for path in Path('/proc/%d/fd' % self.pid).iterdir())

    def set_nofile(self, limit):
        run([str(self.network.prlimit), str(self.pid), str(limit)])

    def logs(self, since=None):
        lines = []
        for line in self.logpath.read_text(errors='replace').splitlines():
            match = re.match(r'^(\d{10}\.\d+) (.*)', line)
            if match and (since is None or float(match[1]) >= since):
                lines.append((float(match[1]), match[2]))
        return lines

    def stop(self):
        if not self.process:
            return
        try:
            os.killpg(self.pid, signal.SIGTERM)
        except ProcessLookupError:
            pass
        try:
            self.process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            os.killpg(self.pid, signal.SIGKILL)
            self.process.wait(timeout=5)
        self.logfile.close()


class Network:
    def __init__(self):
        if os.geteuid() != 0:
            raise RuntimeError('Network tests need root: sudo -E tests/run')
        for program in ('ip', 'iptables', 'tc', 'ss', 'curl', 'nc', 'nginx',
                        'squid', 'danted', 'xinetd', 'useradd', 'userdel', 'chpasswd'):
            if not shutil.which(program):
                raise RuntimeError('Missing native test dependency: ' + program)
        self.binary = Path(os.environ.get('REDSOCKS_BINARY', ROOT.parent / 'redsocks')).resolve()
        self.prlimit = Path(os.environ.get('REDSOCKS_PRLIMIT', ROOT / 'prlimit-nofile')).resolve()
        if not self.binary.is_file() or not self.prlimit.is_file():
            raise RuntimeError('Build redsocks and tests/prlimit-nofile first (tests/build)')
        self.work = Path(os.environ.get('REDSOCKS_TEST_LOG_DIR') or tempfile.mkdtemp(prefix='redsocks-tests-')).resolve()
        self.work.mkdir(parents=True, exist_ok=True)
        self.work.chmod(0o755)
        self.prefix = 'redsocks-%d' % os.getpid()
        self.fabric = self.prefix + '-fabric'
        self.namespaces = []
        self.vm = {}
        self.link_index = 0
        self.account = None
        self.ready = False
        print('Native integration logs: %s' % self.work, flush=True)
        try:
            self.setup()
            self.ready = True
        except BaseException:
            self.close()
            raise

    def setup(self):
        run(['ip', 'netns', 'add', self.fabric])
        self.namespaces.append(self.fabric)
        for subnet in ('web', 'txrx', 'tank'):
            run(['ip', '-n', self.fabric, 'link', 'add', 'br-' + subnet, 'type', 'bridge'])
            run(['ip', '-n', self.fabric, 'link', 'set', 'br-' + subnet, 'up'])

        gw = VM(self, 'gw')
        gw.connect('web', '10.0.1.1', 'ethw')
        gw.connect('txrx', '10.0.8.1', 'ethx')
        gw.netcall('sysctl -qw net.ipv4.ip_forward=1')
        gw.netcall('ip route replace unreachable 10.0.2.0/24')
        gw.netcall('iptables -A FORWARD --destination 10.0.1.66/32 -j DROP')

        web = VM(self, 'web')
        web.connect('web', '10.0.1.80', 'ethw', '10.0.1.1')
        www = self.work / 'www'
        www.mkdir()
        page = b'<html><body>Welcome to nginx!</body></html>\n'
        (www / 'index.html').write_bytes(page + b' ' * (612 - len(page)))
        (www / '1M').write_bytes(bytes(range(256)) * 4096)
        nginx_conf = self.work / 'nginx.conf'
        nginx_conf.write_text('''user root;
worker_processes 1;
pid %s/nginx.pid;
error_log %s/nginx-error.log notice;
events { worker_connections 128; }
http { access_log off; server { listen 80; root %s; } }
''' % (self.work, self.work, www))
        web.start('nginx -c %s -g "daemon off;"' % shlex.quote(str(nginx_conf)), [80])

        inetd = VM(self, 'inetd')
        inetd.connect('web', '10.0.1.13', 'ethw', '10.0.1.1')
        inetd_conf = self.work / 'xinetd.conf'
        inetd_conf.write_text((ROOT / 'inetd/testing').read_text())
        inetd.start('xinetd -dontfork -f %s -pidfile %s/xinetd.pid' %
                    (shlex.quote(str(inetd_conf)), self.work), [7, 9, 13, 19])

        for number in (8, 9):
            proxy = VM(self, 'squid-%d' % number)
            proxy.connect('web', '10.0.1.%d' % number, 'ethw', '10.0.1.1')
            directory = self.work / proxy.name
            directory.mkdir(mode=0o777)
            directory.chmod(0o777)
            for password in ('basic.passwd', 'digest.passwd'):
                shutil.copyfile(ROOT / 'squid' / password, directory / password)
            config = (ROOT / 'squid' / ('squid-%d.conf' % number)).read_text()
            config = config.replace('/usr/lib/squid3/', '/usr/lib/squid/')
            config = config.replace('/etc/squid3/', str(directory) + '/')
            config += '''
visible_hostname redsocks-test
pid_filename %s/squid.pid
cache_log %s/cache.log
access_log none
cache_store_log none
netdb_filename none
coredump_dir %s
shutdown_lifetime 0 seconds
pinger_enable off
''' % (directory, directory, directory)
            conf = directory / 'squid.conf'
            conf.write_text(config)
            proxy.start('squid -NYC -f %s' % shlex.quote(str(conf)), [8080, 8081])

        account = 'rsocktest%d' % os.getpid()
        run(['useradd', '--system', '--no-create-home', '--shell', '/usr/sbin/nologin', account])
        self.account = account
        subprocess.run(['chpasswd'], input=account + ':sockpwd\n', text=True, check=True)
        for number in (0, 1):
            proxy = VM(self, 'dante-%d' % number)
            proxy.connect('web', '10.0.1.%d' % (180 + number), 'ethw', '10.0.1.1')
            config = (ROOT / 'dante' / ('danted-%d.conf' % (1080 + number))).read_text()
            config = re.sub(r'^method:', 'socksmethod:', config, flags=re.MULTILINE)
            config = re.sub(r'^(pass|block) \{', r'socks \1 {', config, flags=re.MULTILINE)
            config = 'user.privileged: root\nuser.notprivileged: nobody\n' + config
            conf = self.work / ('danted-%d.conf' % number)
            conf.write_text(config)
            proxy.start('danted -f %s -p %s/danted-%d.pid' %
                        (shlex.quote(str(conf)), self.work, number), [1080 + number])

        regw = VM(self, 'regw')
        regw.connect('tank', '10.0.2.123', 'etht')
        regw.connect('txrx', '10.0.8.123', 'ethx', '10.0.8.1')
        for tank in TANKS.values():
            regw.netcall('iptables -t nat -A PREROUTING --source 10.0.2.%d/32 '
                         '--dest 10.0.1.0/24 -p tcp -j REDIRECT --to-port %d' %
                         (tank, 12340 + tank - TANKS_BASE))
        config = (ROOT / 'regw/redsocks.conf').read_text().replace('login = sockusr;', 'login = %s;' % account)
        conf = self.work / 'redsocks.conf'
        conf.write_text(config)
        regw.start('%s -c %s' % (shlex.quote(str(self.binary)), shlex.quote(str(conf))), list(range(12340, 12357)))
        for number in TANKS.values():
            tank = VM(self, 'tank%d' % number)
            tank.connect('tank', '10.0.2.%d' % number, 'etht', '10.0.2.123')

    def close(self):
        failures = []
        ordered = sorted(self.vm.values(), key=lambda vm: vm.name != 'regw')
        for vm in ordered:
            try:
                vm.stop()
                if self.ready and vm.name == 'regw':
                    log = vm.logpath.read_text(errors='replace')
                    assert vm.process.returncode == 0, log
                    assert 'redsocks goes down' in log, log
                    assert 'There are connected clients during shutdown' not in log, log
                    assert 'Sanitizer' not in log, log
            except BaseException as error:
                failures.append(error)
        for namespace in reversed(self.namespaces):
            try:
                for pid in run(['ip', 'netns', 'pids', namespace]).split():
                    try:
                        os.kill(int(pid), signal.SIGKILL)
                    except ProcessLookupError:
                        pass
                run(['ip', 'netns', 'del', namespace])
            except BaseException as error:
                failures.append(error)
        self.namespaces.clear()
        if self.account:
            try:
                run(['userdel', self.account])
            except BaseException as error:
                failures.append(error)
            self.account = None
        if failures:
            raise failures[0]
