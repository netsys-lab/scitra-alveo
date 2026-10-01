# Copyright 2013-present Barefoot Networks, Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#   http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

#
# Antonin Bas (antonin@barefootnetworks.com)
#
#

import struct
from bm_runtime.standard.ttypes import *


def bytes_to_string(byte_array):
    form = 'B' * len(byte_array)
    return struct.pack(form, *byte_array)


class MatchType:
    EXACT = 0
    LPM = 1
    TERNARY = 2
    VALID = 3
    RANGE = 4

    @staticmethod
    def to_str(x):
        return {0: "exact", 1: "lpm", 2: "ternary", 3: "valid", 4: "range"}[x]

    @staticmethod
    def from_str(x):
        return {"exact": 0, "lpm": 1, "ternary": 2, "valid": 3, "range": 4}[x]


class UIn_Error(Exception):
    def __init__(self, info=""):
        self.info = info

    def __str__(self):
        return self.info


class UIn_ResourceError(UIn_Error):
    def __init__(self, res_type, name):
        self.res_type = res_type
        self.name = name

    def __str__(self):
        return "Invalid %s name (%s)" % (self.res_type, self.name)


class UIn_MatchKeyError(UIn_Error):
    def __init__(self, info=""):
        self.info = info

    def __str__(self):
        return self.info


class UIn_RuntimeDataError(UIn_Error):
    def __init__(self, info=""):
        self.info = info

    def __str__(self):
        return self.info


class CLI_FormatExploreError(Exception):
    def __init__(self):
        pass


class UIn_BadParamError(UIn_Error):
    def __init__(self, info=""):
        self.info = info

    def __str__(self):
        return self.info


class UIn_BadIPv4Error(UIn_Error):
    def __init__(self):
        pass


class UIn_BadIPv6Error(UIn_Error):
    def __init__(self):
        pass


class UIn_BadMacError(UIn_Error):
    def __init__(self):
        pass


def ipv4Addr_to_bytes(addr):
    if not '.' in addr:
        raise CLI_FormatExploreError()
    s = addr.split('.')
    if len(s) != 4:
        raise UIn_BadIPv4Error()
    try:
        return [int(b) for b in s]
    except:
        raise UIn_BadIPv4Error()


def macAddr_to_bytes(addr):
    if not ':' in addr:
        raise CLI_FormatExploreError()
    s = addr.split(':')
    if len(s) != 6:
        raise UIn_BadMacError()
    try:
        return [int(b, 16) for b in s]
    except:
        raise UIn_BadMacError()


def ipv6Addr_to_bytes(addr):
    from ipaddress import IPv6Address
    if not ':' in addr:
        raise CLI_FormatExploreError()
    try:
        ip = IPv6Address(addr)
    except:
        raise UIn_BadIPv6Error()
    try:
        return list(ip.packed)
    except:
        raise UIn_BadIPv6Error()


def int_to_bytes(i, num):
    byte_array = []
    while i > 0:
        byte_array.append(i % 256)
        i = i // 256
        num -= 1
    if num < 0:
        raise UIn_BadParamError("Parameter is too large")
    while num > 0:
        byte_array.append(0)
        num -= 1
    byte_array.reverse()
    return byte_array


def parse_param(input_str, bitwidth):
    if bitwidth == 32:
        try:
            return ipv4Addr_to_bytes(input_str)
        except CLI_FormatExploreError:
            pass
        except UIn_BadIPv4Error:
            raise UIn_BadParamError("Invalid IPv4 address")
    elif bitwidth == 48:
        try:
            return macAddr_to_bytes(input_str)
        except CLI_FormatExploreError:
            pass
        except UIn_BadMacError:
            raise UIn_BadParamError("Invalid MAC address")
    elif bitwidth == 128:
        try:
            return ipv6Addr_to_bytes(input_str)
        except CLI_FormatExploreError:
            pass
        except UIn_BadIPv6Error:
            raise UIn_BadParamError("Invalid IPv6 address")
    try:
        input_ = int(input_str, 0)
    except:
        raise UIn_BadParamError(
            "Invalid input, could not cast to integer, try in hex with 0x prefix"
        )
    try:
        return int_to_bytes(input_, (bitwidth + 7) // 8)
    except UIn_BadParamError:
        raise


def parse_runtime_data(action, params):
    def parse_param_(field, bw):
        try:
            return parse_param(field, bw)
        except UIn_BadParamError as e:
            raise UIn_RuntimeDataError(
                "Error while parsing %s - %s" % (field, e)
            )

    bitwidths = [bw for(_, bw) in action.runtime_data]
    byte_array = []
    for input_str, bitwidth in zip(params, bitwidths):
        byte_array += [bytes_to_string(parse_param_(input_str, bitwidth))]
    return byte_array


_match_types_mapping = {
    MatchType.EXACT: BmMatchParamType.EXACT,
    MatchType.LPM: BmMatchParamType.LPM,
    MatchType.TERNARY: BmMatchParamType.TERNARY,
    MatchType.VALID: BmMatchParamType.VALID,
    MatchType.RANGE: BmMatchParamType.RANGE,
}

def parse_match_key(table, key_fields):

    def parse_param_(field, bw):
        try:
            return parse_param(field, bw)
        except UIn_BadParamError as e:
            raise UIn_MatchKeyError(
                "Error while parsing %s - %s" % (field, e)
            )

    params = []
    match_types = [t for (_, t, _) in table.key]
    bitwidths = [bw for (_, _, bw) in table.key]
    for idx, field in enumerate(key_fields):
        param_type = _match_types_mapping[match_types[idx]]
        bw = bitwidths[idx]
        if param_type == BmMatchParamType.EXACT:
            key = bytes_to_string(parse_param_(field, bw))
            param = BmMatchParam(type=param_type,
                                 exact=BmMatchParamExact(key))
        elif param_type == BmMatchParamType.LPM:
            try:
                prefix, length = field.split("/")
            except ValueError:
                raise UIn_MatchKeyError(
                    "Invalid LPM value {}, use '/' to separate prefix "
                    "and length".format(field))
            key = bytes_to_string(parse_param_(prefix, bw))
            param = BmMatchParam(type=param_type,
                                 lpm=BmMatchParamLPM(key, int(length)))
        elif param_type == BmMatchParamType.TERNARY:
            try:
                key, mask = field.split("&&&")
            except ValueError:
                raise UIn_MatchKeyError(
                    "Invalid ternary value {}, use '&&&' to separate key and "
                    "mask".format(field))
            key = bytes_to_string(parse_param_(key, bw))
            mask = bytes_to_string(parse_param_(mask, bw))
            if len(mask) != len(key):
                raise UIn_MatchKeyError(
                    "Key and mask have different lengths in expression %s" % field
                )
            param = BmMatchParam(type=param_type,
                                 ternary=BmMatchParamTernary(key, mask))
        elif param_type == BmMatchParamType.VALID:
            key = bool(int(field))
            param = BmMatchParam(type=param_type,
                                 valid=BmMatchParamValid(key))
        elif param_type == BmMatchParamType.RANGE:
            try:
                start, end = field.split("->")
            except ValueError:
                raise UIn_MatchKeyError(
                    "Invalid range value {}, use '->' to separate range start "
                    "and range end".format(field))
            start = bytes_to_string(parse_param_(start, bw))
            end = bytes_to_string(parse_param_(end, bw))
            if len(start) != len(end):
                raise UIn_MatchKeyError(
                    "start and end have different lengths in expression %s" % field
                )
            if start > end:
                raise UIn_MatchKeyError(
                    "start is less than end in expression %s" % field
                )
            param = BmMatchParam(type=param_type,
                                 range=BmMatchParamRange(start, end))
        else:
            assert(0)
        params.append(param)
    return params
