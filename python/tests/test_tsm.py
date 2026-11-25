"""ConfigfsTsm against an emulated configfs-tsm (the same cases as the Go gate's TestConfigfsTsm)."""

import os
import types

import pytest

from chutes_tdx_gate import attest


class FakeConfigfs:
    """mkdir creates provider and generation; a write to inblob bumps generation and makes
    outblob; ``interleave`` extra writers bump generation again before the second read."""

    def __init__(self, provider=b"tdx_guest", interleave=0):
        self.provider, self.interleave = provider, interleave
        self.files, self.fds, self.inblobs, self.removed = {}, {}, [], 0

    def namespace(self):
        return types.SimpleNamespace(mkdir=self.mkdir, rmdir=self.rmdir, open=self.open, write=self.write,
                                     close=self.close, O_WRONLY=os.O_WRONLY, path=os.path)

    def mkdir(self, path):
        self.files[path + "/provider"] = self.provider + b"\n"
        self.files[path + "/generation"] = b"0\n"

    def rmdir(self, path):
        self.removed += 1

    def open(self, path, flags):
        assert path.endswith("/inblob") and flags == os.O_WRONLY
        fd = len(self.fds) + 100
        self.fds[fd] = path
        return fd

    def write(self, fd, data):
        path = self.fds[fd]
        entry = path.rsplit("/", 1)[0]
        self.inblobs.append(bytes(data))
        generation = int(self.files[entry + "/generation"]) + 1
        self.files[entry + "/generation"] = b"%d\n" % generation
        quote = bytearray(640)
        quote[0:2], quote[4:8], quote[568:632] = (4).to_bytes(2, "little"), (0x81).to_bytes(4, "little"), data
        self.files[entry + "/outblob"] = bytes(quote)
        return len(data)

    def close(self, fd):
        pass

    def read(self, path):
        if path.endswith("/generation") and self.interleave and (path.rsplit("/", 1)[0] + "/outblob") in self.files:
            self.files[path] = b"%d\n" % (int(self.files[path]) + 1)
            self.interleave -= 1
        return self.files[path]


@pytest.fixture
def fake(monkeypatch):
    def install(**kw):
        fs = FakeConfigfs(**kw)
        monkeypatch.setattr(attest, "os", fs.namespace())
        monkeypatch.setattr(attest.ConfigfsTsm, "_read", staticmethod(fs.read))
        return fs
    return install


def test_quote(fake):
    fs = fake()
    rd = bytes(range(64))
    quote = attest.ConfigfsTsm("/x").quote(rd)
    attest.check_quote(quote, rd)
    assert fs.inblobs == [rd] and fs.removed == 1


def test_one_interleaved_writer_is_retried(fake):
    fake(interleave=1)
    attest.ConfigfsTsm("/x").quote(bytes(64))


def test_two_interleaved_writers_are_busy(fake):
    fs = fake(interleave=2)
    with pytest.raises(attest.TsmBusy):
        attest.ConfigfsTsm("/x").quote(bytes(64))
    assert fs.removed == 2


def test_another_provider_is_refused(fake):
    fs = fake(provider=b"sev_guest")
    with pytest.raises(RuntimeError):
        attest.ConfigfsTsm("/x").quote(bytes(64))
    assert fs.inblobs == []


def test_check_quote():
    rd = bytes(range(64))
    quote = bytearray(640)
    quote[0:2], quote[4:8], quote[568:632] = (4).to_bytes(2, "little"), (0x81).to_bytes(4, "little"), rd
    attest.check_quote(bytes(quote), rd)
    for bad in (bytes(quote[:600]), b"\x05" + bytes(quote[1:]), bytes(quote[:4]) + b"\x00" + bytes(quote[5:])):
        with pytest.raises(ValueError):
            attest.check_quote(bad, rd)
    with pytest.raises(ValueError):
        attest.check_quote(bytes(quote), bytes(64))
