"""Collect the portable C parser checks in the shared pytest suite."""
import os
from pathlib import Path
import shlex
import subprocess


def test_tls_sni_parser(tmp_path):
    source = Path(__file__).resolve().parent.parent
    binary = tmp_path / 'test_tls_sni'
    compiler = shlex.split(os.environ.get('CC', 'cc'))
    cppflags = shlex.split(os.environ.get('CPPFLAGS', ''))
    cflags = shlex.split(os.environ.get('CFLAGS', '-O2 -g'))
    ldflags = shlex.split(os.environ.get('LDFLAGS', ''))
    subprocess.run([
        *compiler, *cppflags, *cflags, '-std=c99', '-Wall', '-Wextra',
        '-Werror', '-UNDEBUG', '-I' + str(source),
        str(source / 'tls-sni.c'), str(source / 'tests/test_tls_sni.c'),
        *ldflags, '-o', str(binary),
    ], check=True, timeout=120)
    subprocess.run([str(binary)], check=True, timeout=30)
