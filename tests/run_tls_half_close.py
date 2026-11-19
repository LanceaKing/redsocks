"""Supply temporary server credentials for the real TLS half-close regression."""
from pathlib import Path
import subprocess
import sys
import tempfile


def main():
    with tempfile.TemporaryDirectory(prefix="redsocks-tls-half-close-") as temporary:
        directory = Path(temporary)
        certificate, key = directory / "certificate.pem", directory / "key.pem"
        subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
                        "-days", "1", "-subj", "/CN=half-close.test", "-keyout", str(key),
                        "-out", str(certificate)], check=True, stdout=subprocess.DEVNULL,
                       stderr=subprocess.DEVNULL)
        subprocess.run([sys.argv[1], str(certificate), str(key)], check=True)


if __name__ == "__main__":
    main()
