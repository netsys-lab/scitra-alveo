# SPDX-License-Identifier: AGPL-3.0-or-later

import fcntl
import functools
import io
import os
import subprocess
import time
import unittest
from itertools import zip_longest
from typing import Dict, List, Tuple

import psutil
from bm_runtime.standard import Standard
from bm_runtime.standard.ttypes import BmAddEntryOptions
from bm_vitisnetp4_runtime import BmVitisNetP4
from runtime_CLI import (
    SUFFIX_LOOKUP_MAP, MatchType, ResType, UIn_Error, UIn_ResourceError,
    load_json_str,
)
from scapy.packet import Packet
from scapy_scion.utils import compare_layers
from thrift.protocol import TBinaryProtocol, TMultiplexedProtocol
from thrift.transport import TSocket, TTransport
from .tools import parse_match_key, parse_runtime_data


class ModelError(Exception):
    pass


def term_recursive(pid: int):
    """Terminate process an all children.
    Can miss some processes if new children are spawned while others are terminated.
    """
    proc = psutil.Process(pid)
    for p in reversed(proc.children(recursive=True)):
        p.terminate()
    proc.terminate()


def _get_res(type_name, name, res_type):
    # Copied from RuntimeAPI
    key = res_type, name
    if key not in SUFFIX_LOOKUP_MAP:
        raise UIn_ResourceError(type_name, name)
    return SUFFIX_LOOKUP_MAP[key]


def compare_packets(packet1, packet2):
    """Compare two packets layer by layer."""
    layers1, layers2 = packet1.layers(), packet2.layers()
    for i, (layer1, layer2) in enumerate(zip(layers1, layers2)):
        if layer1 is not layer2:
            yield ("Layer", str(i), packet1[i].name, packet2[i].name)
            break
        for field, a, b in compare_layers(packet1[i], packet2[i]):
            yield (f"{packet1[i].name}({i})", field, a, b)


Metadata = Dict[str, int]


class BMRuntime:
    """Offers access to the thrift control plane API of the behavioral model.

    Combines the standard thrift API and the proprietary extensions for
    VitisNetP4 in one Python interface. Commands concerning features specific to
    simple_switch and other BMv2 architectures naturally don't work in VitisP4.
    The VitisNetP4 extensions consist of the functions `exit` and `run_traffic`.
    `run_traffic` is the only way to send data through the VitisNetP4 model.
    """

    def __init__(self):
        self.transport = None
        self.clients = None

    def connect(self, thrift_ip = "localhost", thrift_port = 9900, attempts=5):
        if self.transport:
            return

        # Connect to switch
        self.transport = TTransport.TBufferedTransport(TSocket.TSocket(
            thrift_ip, thrift_port))
        bprotocol = TBinaryProtocol.TBinaryProtocol(self.transport)
        self.clients = {}
        self.clients["standard"] = Standard.Client(
            TMultiplexedProtocol.TMultiplexedProtocol(bprotocol, "standard"))
        self.clients["vitisnetp4"] = BmVitisNetP4.Client(
            TMultiplexedProtocol.TMultiplexedProtocol(bprotocol, "bm_vitisnetp4"))

        attempt = 0
        while True:
            try:
                self.transport.open()
                break
            except TTransport.TTransportException as e:
                if e.type == TTransport.TTransportException.NOT_OPEN:
                    if attempt < attempts:
                        time.sleep(0.1)
                        continue
                raise

        # Load dataplane JSON from model
        load_json_str(self.clients["standard"].bm_get_config())

    def is_open(self):
        return self.transport and self.transport.isOpen()

    def close(self):
        if self.is_open():
            self.transport.close()
            self.transport = None
            self.clients = None

    def table_add(self, table_name: str,
                  match_key: List[bytes], # list of keys as expected by the CLI
                  action_name: str, action_params: List[str],
                  priority: int = 0) -> int:
        """Add a table entry. Returns the new entry ID.
        """
        table = _get_res("table", table_name, ResType.table)

        action = table.get_action(action_name)
        if action is None:
            raise UIn_Error(
                "Table %s has no action %s" % (table_name, action_name)
            )

        key = parse_match_key(table, match_key)

        if len(action_params) != action.num_params():
            raise UIn_Error(
                "Action %s needs %d parameters" % (
                    action.name, action.num_params())
            )

        action_args = parse_runtime_data(action, action_params)

        entry_handle = self.clients["standard"].bm_mt_add_entry(
            0, table.name, key, action.name, action_args,
            BmAddEntryOptions(priority=priority)
        )
        return entry_handle

    def table_delete(self, table_name: str, handle: int):
        """Delete the entry with ID `handle` from the table."""
        table = _get_res("table", table_name, ResType.table)
        self.clients["standard"].bm_mt_delete_entry(0, table.name, handle)

    def table_clear(self, table_name: str):
        """Clear all table entries and reset the default entry to the default
        default.
        """
        table = _get_res("table", table_name, ResType.table)
        self.clients["standard"].bm_mt_clear_entries(0, table.name, True)

    def table_dump(self, table_name: str) -> List[Tuple]:
        """Returns all table entries except the default one."""
        table = _get_res("table", table_name, ResType.table)
        entries = []
        for e in self.clients["standard"].bm_mt_get_entries(0, table.name):
            for p, k in zip(e.match_key, table.key):
                mt = MatchType.to_str(p.type).lower()
                entries.append((k, mt, p))
        return entries

    def counter_read(self, counter_name: str, index: int) -> int | Tuple[int, int]:
        """Read a counter value. If the counter is of PACKETS_AND_BYTES type,
        returns a tuple of packets and bytes, otherwise just an integer.
        """
        counter = _get_res("counter", counter_name, ResType.counter_array)
        assert not counter.is_direct # not possible in Vitis P4
        config = self.clients["standard"].bm_counter_read_config(0, counter.name)
        assert 0 <= index < config.size
        value = self.clients["standard"].bm_counter_read(0, counter.name, index)
        if config.type == 0:
            return value.bytes
        elif config.type == 1:
            return value.packets
        elif config.type == 2:
            return (value.packets, value.bytes)
        elif config.type == 3: # single bit
            return 1 if value.latch else 0
        else:
            assert False # not possible in Vitis P4

    def send_packets(
            self, pkts: List[Packet], meta: List[Metadata],
            tmp_path: str = ".", base_name: str = "packets"
            ) -> Tuple[List[Packet], List[Metadata]]:
        """Sends one or more packets through the VitisNetP4 pipeline and returns
        the resulting transformed packets.

        Since the model only supports packet I/O via files, the packet and
        metadata is written to a temporary directory.
        """

        pkts_in = os.path.join(tmp_path, f"{base_name}_in.user")
        meta_in = os.path.join(tmp_path, f"{base_name}_in.meta")
        pkts_out = os.path.join(tmp_path, f"{base_name}_out.user")
        meta_out = os.path.join(tmp_path, f"{base_name}_out.meta")

        # Create input files
        with open(pkts_in, "wt") as fpkts, open(meta_in, "wt") as fmeta:
            for i, (pkt, meta) in enumerate(zip_longest(pkts, meta)):
                # Packet
                print(f"% Packet {i+1} ({len(pkt)} bytes)", file=fpkts)
                print(bytes(pkt).hex(sep=" "), end=";\n", file=fpkts)
                # Metadata
                print(f"% Packet {i+1}", file=fmeta)
                if meta is not None:
                    for field, value in meta.items():
                        print("{}={:x}".format(field, value), file=fmeta)
                print(";", file=fmeta)

        # Run model
        self.clients["vitisnetp4"].run_traffic(["packets"])

        # Parse output files
        out = []
        pkt = b""
        with open(pkts_out, "rt") as fpkts:
            for line in fpkts.readlines():
                if line.lstrip().startswith("%"):
                    continue
                pkt += bytes.fromhex(line.rstrip(" ;\n"))
                if line.rstrip().endswith(";"):
                    out.append(pkt)
                    pkt = b""

        out_meta = []
        metadata = {}
        with open(meta_out, "rt") as fmeta:
            for line in fmeta.readlines():
                if line.lstrip().startswith("%"):
                    continue
                for part in line.rstrip(" ;\n").split():
                    field, value = part.split("=")
                    metadata[field] = int.from_bytes(bytes.fromhex(value))
                if line.rstrip().endswith(";"):
                    out_meta.append(metadata)
                    metadata = {}

        return out, out_meta


    def exit_model(self):
        """Shuts the simulation model down."""
        self.clients["vitisnetp4"].exit()

def dump_log_on_fail(f):
    @functools.wraps(f)
    def wrapper(self, *args, **kwargs):
        try:
            return f(self, *args, **kwargs)
        except AssertionError:
            print ("================================ Begin Model Log ================================")
            print(self.read_model_log())
            print("================================== End Model Log =================================")
            raise
    return wrapper


class BMVitisP4TestCase(unittest.TestCase):
    """Base class for Vitis P4 behavioral model test cases.

    Starts p4bm-vitisnet with the dataplane given to setUp().
    Make sure to override setUp() in all test cases and call the base setUp()
    with the correct dataplane.
    """
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.bm: subprocess.Popen = None
        self.runtime: BMRuntime = None

    def setUp(self, dataplane: str, emit_dropped: bool = True, thrift_port: int = 9900):
        """
        ### Parameters
        emit_dropped: Emit dropped packet as zero-length packets.
        thrift_port: Thrift port for communicating with p4bm-vitisnet-cli.
        """
        cmd = ["p4bm-vitisnet",
             "--log-console",
             "--thrift-port", str(thrift_port),
             dataplane]
        if emit_dropped:
            cmd += ["--", "--drop-zero-length"]
        self.bm = subprocess.Popen(" ".join(cmd), encoding="utf8", shell=True,
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        # Increase PIPE capacity to 1MB (commonly the maximum allowed in Linux)
        # and set to nen-blocking so we can read some output while the model
        # is running.
        # WARNING: If the pipe becomes full during a test, the test will
        # deadlock since we only drain the pipe afterwards.
        fcntl.fcntl(self.bm.stdout.fileno(), fcntl.F_SETPIPE_SZ, 1024*1024)
        os.set_blocking(self.bm.stdout.fileno(), False)
        time.sleep(0.1) # wait before trying to connect to model
        self.runtime = BMRuntime()
        try:
            self.runtime.connect(thrift_port=thrift_port)
        except Exception as e:
            if self.bm.poll() is not None:
                raise ModelError(self.read_model_log())
            raise
        # Discard initialization log
        self.read_model_log()

    def tearDown(self):
        if self.runtime.is_open():
            self.runtime.exit_model()
            self.runtime.close()
        else:
            if self.bm.poll() is None:
                # p4bm is executed by a chain of shell scripts, terminate all
                term_recursive(self.bm.pid)
        self.bm.stdout.close()
        self.bm.wait()

    def read_model_log(self) -> str:
        return self.bm.stdout.read()

    def assertPacket(self, first, second, msg=None):
        diff = io.StringIO()
        printed_header = False
        for layer, field, aval, eval in compare_packets(first, second):
            if not printed_header:
                diff.write("\nDifferences:")
                diff.write("\n{:<12} {:<30} {:>25} {:>25}\n".format(
                    "Layer", "Field", "First", "Second"))
                diff.write(95*"-")
                diff.write("\n")
                printed_header = True
            diff.write("{:<12} {:<30} {:>25} {:>25}\n".format(layer, field, str(aval), str(eval)))
        if printed_header:
            self.fail("Packet assertion failed" + (f": {msg}" if msg else "") + diff.getvalue())
