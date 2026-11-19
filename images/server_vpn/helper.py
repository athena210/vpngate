#!/usr/bin/env python3

from __future__ import annotations

import datetime as dt
import ipaddress
import json
import base64
import os
import re
import sys
from datetime import datetime
from zoneinfo import ZoneInfo
from dataclasses import asdict, dataclass, field, replace
import libknot.control
import nftables
from jinja2 import Environment, StrictUndefined

# import binascii
# import vici
# from cryptography import x509


DEBUG_LEVEL = 0
DEBUG_FILE = "/vpnstat/debug.txt"
AUTH_DB_FILE = "/vpn/ovpn/users.list"
PROFILES_DIR = "/vpn/ovpn/profiles"
KNOT_UNIX_SOCKET = "/run/knot/knot.sock"
USERID = "CN"
DNS_CLIENT_SUFFIX = "-vpn"
DNS_RECORDS_TTL = "30"
DNS_ZONE_NAME_FILE = "/VPN_DNS_ZONE"


@dataclass(frozen=True, slots=True, kw_only=True)
class VpnContext:
    auth_db_file: str = AUTH_DB_FILE
    profiles_db_dir: str = PROFILES_DIR
    knot_socket_file: str = KNOT_UNIX_SOCKET
    cert_userid_field: str = USERID
    dns_client_suffix: str = DNS_CLIENT_SUFFIX
    dns_client_ttl: str = DNS_RECORDS_TTL
    dns_zone_name_file: str = DNS_ZONE_NAME_FILE
    dns_zone_name: str | None = None
    is_ovpn: bool | None = None
    is_swan: bool | None = None
    debug_file: str | None = DEBUG_FILE
    debug_level: int | None = None

    # both
    instance: str | None = None
    cmdline: tuple[str, ...] = field(default_factory=tuple)
    user_ip: str | None = None
    user_ptr: str | None = None
    ip_version: str | None = None
    userid: str | None = None
    user_ip4: str | None = None
    user_ptr4: str | None = None
    server_ip4: str | None = None
    server_mask4: str | None = None
    user_ip6: str | None = None
    user_ptr6: str | None = None
    server_ip6: str | None = None
    server_mask6: str | None = None

    # ovpn
    script_type: str | None = None
    learn_cmd: str | None = None
    user_auth: str | None = None
    user_auth_name: str | None = None
    user_auth_profiles: tuple[str, ...] = field(default_factory=tuple)
    user_password: str | None = None
    response_file: str | None = None

    # swan
    pluto_verb: str | None = None

    def to_json(self) -> str:
        return json.dumps(asdict(self), ensure_ascii=False)

    @classmethod
    def from_json(cls, raw: str) -> VpnContext:
        return cls(**json.loads(raw))


def debug(
    ctx: VpnContext,
    msg: str,
    *,
    with_timestamp: bool = True,
    with_newline: bool = True,
    level: int = 3,
) -> None:
    # debug_file:             str | None  = DEBUG_FILE
    # debug_level:            int | None  = None

    if (
        not ctx
        or not ctx.debug_file
        or not ctx.debug_level
        or level < ctx.debug_level
        or level < 1
    ):
        return

    time = (
        f"{dt.datetime.now().strftime('%Y-%m-%d %H-%M-%S')}: " if with_timestamp else ""
    )
    newline = "\n" if with_newline else ""

    try:
        with open(ctx.debug_file, "a+", encoding="utf-8") as out:
            out.write(f"{time}{msg}{newline}")
    except OSError:
        pass

    return


class NftManager:
    def __init__(self):
        self.table_name = "my_firewall"
        self.nat_chain = "vpn_nat"
        self.forward_chain = "vpn_forward"
        self.family = "inet"
        self.nft = nftables.Nftables()
        self.nft.set_json_output(True)

    def _run_cmd(self, cmd):
        payload = {"nftables": cmd}
        rc, output, error = self.nft.json_cmd(payload)
        if rc != 0:
            raise RuntimeError(f"Nftables error: {error}")
        return output

    def add_masquerade(self, *, tag: str, user_ip: str, ip_version: str) -> int:
        proto = "ip" if ip_version == "4" else "ip6"
        cmd = [
            {
                "add": {
                    "rule": {
                        "family": self.family,
                        "table": self.table_name,
                        "chain": self.nat_chain,
                        "comment": tag,
                        "expr": [
                            {
                                "match": {
                                    "op": "==",
                                    "left": {
                                        "payload": {"protocol": proto, "field": "saddr"}
                                    },
                                    "right": user_ip,
                                }
                            },
                            {"masquerade": None},
                        ],
                    }
                }
            }
        ]
        try:
            self._run_cmd(cmd)
        except RuntimeError:
            return 1
        return 0

    def add_internet_access(self, *, tag: str, user_ip: str, ip_version: str) -> int:
        proto = "ip" if ip_version == "4" else "ip6"
        lan_set = f"@rfclans_v{ip_version}"

        cmd = []
        # client to inet
        cmd.append(
            {
                "add": {
                    "rule": {
                        "family": self.family,
                        "table": self.table_name,
                        "chain": self.forward_chain,
                        "comment": tag,
                        "expr": [
                            {
                                "match": {
                                    "op": "==",
                                    "left": {
                                        "payload": {"protocol": proto, "field": "saddr"}
                                    },
                                    "right": user_ip,
                                }
                            },
                            {
                                "match": {
                                    "op": "!=",
                                    "left": {
                                        "payload": {"protocol": proto, "field": "daddr"}
                                    },
                                    "right": lan_set,
                                }
                            },
                            {"accept": None},
                        ],
                    }
                }
            }
        )

        # inet to client
        cmd.append(
            {
                "add": {
                    "rule": {
                        "family": self.family,
                        "table": self.table_name,
                        "chain": self.forward_chain,
                        "comment": tag,
                        "expr": [
                            {
                                "match": {
                                    "op": "==",
                                    "left": {
                                        "payload": {"protocol": proto, "field": "daddr"}
                                    },
                                    "right": user_ip,
                                }
                            },
                            {
                                "match": {
                                    "op": "!=",
                                    "left": {
                                        "payload": {"protocol": proto, "field": "saddr"}
                                    },
                                    "right": lan_set,
                                }
                            },
                            {"accept": None},
                        ],
                    }
                }
            }
        )
        try:
            self._run_cmd(cmd)
        except RuntimeError:
            return 1
        return 0

    def add_full_access(self, *, tag: str, user_ip: str, ip_version: str) -> int:
        proto = "ip" if ip_version == "4" else "ip6"

        cmd = []
        # from client
        cmd.append(
            {
                "add": {
                    "rule": {
                        "family": self.family,
                        "table": self.table_name,
                        "chain": self.forward_chain,
                        "comment": tag,
                        "expr": [
                            {
                                "match": {
                                    "op": "==",
                                    "left": {
                                        "payload": {"protocol": proto, "field": "saddr"}
                                    },
                                    "right": user_ip,
                                }
                            },
                            {"accept": None},
                        ],
                    }
                }
            }
        )

        # to client
        cmd.append(
            {
                "add": {
                    "rule": {
                        "family": self.family,
                        "table": self.table_name,
                        "chain": self.forward_chain,
                        "comment": tag,
                        "expr": [
                            {
                                "match": {
                                    "op": "==",
                                    "left": {
                                        "payload": {"protocol": proto, "field": "daddr"}
                                    },
                                    "right": user_ip,
                                }
                            },
                            {"accept": None},
                        ],
                    }
                }
            }
        )
        try:
            self._run_cmd(cmd)
        except RuntimeError:
            return 1
        return 0

    def add_subnet_access(
        self, *, tag: str, user_ip: str, ip_version: str, net_addr: str, net_len: str
    ) -> int:

        proto = "ip" if ip_version == "4" else "ip6"
        cmd = []

        # client to net
        cmd.append(
            {
                "add": {
                    "rule": {
                        "family": self.family,
                        "table": self.table_name,
                        "chain": self.forward_chain,
                        "comment": tag,
                        "expr": [
                            {
                                "match": {
                                    "op": "==",
                                    "left": {
                                        "payload": {"protocol": proto, "field": "saddr"}
                                    },
                                    "right": user_ip,
                                }
                            },
                            {
                                "match": {
                                    "op": "==",
                                    "left": {
                                        "payload": {"protocol": proto, "field": "daddr"}
                                    },
                                    "right": {
                                        "prefix": {
                                            "addr": net_addr,
                                            "len": int(net_len),
                                        }
                                    },
                                }
                            },
                            {"accept": None},
                        ],
                    }
                }
            }
        )

        # net to client
        cmd.append(
            {
                "add": {
                    "rule": {
                        "family": self.family,
                        "table": self.table_name,
                        "chain": self.forward_chain,
                        "comment": tag,
                        "expr": [
                            {
                                "match": {
                                    "op": "==",
                                    "left": {
                                        "payload": {"protocol": proto, "field": "saddr"}
                                    },
                                    "right": {
                                        "prefix": {
                                            "addr": net_addr,
                                            "len": int(net_len),
                                        }
                                    },
                                }
                            },
                            {
                                "match": {
                                    "op": "==",
                                    "left": {
                                        "payload": {"protocol": proto, "field": "daddr"}
                                    },
                                    "right": user_ip,
                                }
                            },
                            {"accept": None},
                        ],
                    }
                }
            }
        )

        try:
            self._run_cmd(cmd)
        except RuntimeError:
            return 1
        return 0

    def delete_by_tag(self, *, tag: str) -> int:
        current_rules = []
        try:
            current_rules = self._run_cmd([{"list": {"ruleset": None}}])
        except RuntimeError:
            return 1
        cmd = []
        for item in current_rules.get("nftables", []):
            if "rule" not in item:
                continue
            rule = item["rule"]
            if rule.get("table") == self.table_name and rule.get("comment") == tag:
                cmd.append(
                    {
                        "delete": {
                            "rule": {
                                "family": self.family,
                                "table": self.table_name,
                                "chain": rule["chain"],
                                "handle": rule["handle"],
                            }
                        }
                    }
                )
        if not cmd:
            return 0

        try:
            self._run_cmd(cmd)
        except RuntimeError:
            return 1

        return 0


def _get_peer_dn(*, uniqueid: str | None) -> str | None:
    # if not uniqueid:
    #     return None

    # try:
    #     session = vici.Session()
    #     request = {
    #         "noblock": "yes"
    #     }
    #     sas = session.streamed_request("list-sas", "list-sa", request)
    #     for sa in sas:
    #         for _, ike_sa in sa.items():
    #             uid = ike_sa.get("uniqueid")
    #             cert_hex = ike_sa.get("remote-cert-data")
    #             if (
    #                 not uid or
    #                 not cert_hex
    #             ):
    #                 continue

    #             uid = uid.decode('utf-8')
    #             if uid != uniqueid:
    #                 continue

    #             if cert_hex.startswith("0x"):
    #                 cert_hex = cert_hex[2:]

    #             cert_der = binascii.unhexlify(cert_hex)
    #             cert = x509.load_der_x509_certificate(cert_der)
    #             return cert.subject.rfc4514_string()
    # except Exception as e:
    #     pass

    return None


def _var_read_dns_zone_name(ctx: VpnContext) -> dict | None:

    if not ctx or not ctx.dns_zone_name_file:
        return None

    dns_zone_name = None
    try:
        with open(ctx.dns_zone_name_file, "r", encoding="utf-8-sig") as f:
            dns_zone_name = f.read().strip()
    except OSError:
        debug(ctx, f"ZONE-NAME. Cant read var file: {ctx.dns_zone_name_file}")
        return None

    if not dns_zone_name:
        debug(ctx, "ZONE-NAME. DNS zone name is empty.")
        return None

    # linter type checking
    retc = VpnContext(dns_zone_name=dns_zone_name)

    return {"dns_zone_name": retc.dns_zone_name}


def _collect_ovpn_data(ctx: VpnContext) -> dict | None:
    is_ovpn = True
    instance            = os.getenv("instance")
    cmdline             = tuple(sys.argv[1:]) if len(sys.argv) > 1 else tuple()
    userid              = os.getenv(f"X509_0_{ctx.cert_userid_field.upper()}")
    script_type         = os.getenv("script_type")
    server_ip4_txt      = os.getenv("ifconfig_local") or "999"
    server_mask4_txt    = os.getenv("ifconfig_netmask") or "999"
    server_ip6_txt      = os.getenv("ifconfig_ipv6_local") or "999"
    server_mask6_txt    = os.getenv("ifconfig_ipv6_netbits") or "999"
    user_ip4_txt        = os.getenv("ifconfig_pool_remote_ip") or "999"
    user_ip6_txt        = os.getenv("ifconfig_pool_remote_ip6") or "999"
    user_auth           = os.getenv("username")

    server_ip4      = None
    server_mask4    = None
    server_ip6      = None
    server_mask6    = None
    try:
        _ = ipaddress.ip_interface(f"{server_ip4_txt}/{server_mask4_txt}")
        server_ip4 = server_ip4_txt
        server_mask4 = server_mask4_txt
    # trunk-ignore(bandit/B110)
    except Exception:
        pass

    try:
        _ = ipaddress.ip_interface(f"{server_ip6_txt}/{server_mask6_txt}")
        server_ip6 = server_ip6_txt
        server_mask6 = server_mask6_txt
    # trunk-ignore(bandit/B110)
    except Exception:
        pass

    user_ip4, user_ptr4, _ = _parse_ipaddr(user_ip4_txt)
    user_ip6, user_ptr6, _ = _parse_ipaddr(user_ip6_txt)

    learn_cmd = None
    user_ip_txt = None
    user_password = None
    response_file = None
    match script_type:
        case "client-connect":
            if len(cmdline) == 1:
                response_file = cmdline[0]
            else:
                debug(ctx, f"oCOLLECT. Bad args num for {script_type}: {len(cmdline)}")

        case "user-pass-verify":
            if len(cmdline) == 1:
                user_auth_file = cmdline[0]
                user_auth, user_password = _parse_ovpn_auth_file(user_auth_file)
            else:
                debug(ctx, f"oCOLLECT. Bad args num for {script_type}: {len(cmdline)}")

        case "learn-address":
            if len(cmdline) == 2 or len(cmdline) == 3:
                learn_cmd = cmdline[0].lower()
                user_ip_txt = cmdline[1]
                userid = cmdline[2] if len(cmdline) > 2 else None
            else:
                debug(ctx, f"oCOLLECT. Bad args num for {script_type}: {len(cmdline)}")

    user_ip, user_ptr, ip_version = _parse_ipaddr(user_ip_txt)
    user_auth_name, user_auth_profiles = _parse_user_auth_str(user_auth)

    # linter type checking
    retc = VpnContext(
        is_ovpn=is_ovpn,
        instance=instance,
        cmdline=cmdline,
        userid=userid,
        user_ip4=user_ip4,
        user_ptr4=user_ptr4,
        server_ip4=server_ip4,
        server_mask4=server_mask4,
        user_ip6=user_ip6,
        user_ptr6=user_ptr6,
        server_ip6=server_ip6,
        server_mask6=server_mask6,
        learn_cmd=learn_cmd,
        user_ip=user_ip,
        user_ptr=user_ptr,
        ip_version=ip_version,
        script_type=script_type,
        user_auth=user_auth,
        user_auth_name=user_auth_name,
        user_auth_profiles=user_auth_profiles,
        user_password=user_password,
        response_file=response_file,
    )

    return {
        "is_ovpn": retc.is_ovpn,
        "instance": retc.instance,
        "cmdline": retc.cmdline,
        "userid": retc.userid,
        "user_ip4": retc.user_ip4,
        "user_ptr4": retc.user_ptr4,
        "server_ip4": retc.server_ip4,
        "server_mask4": retc.server_mask4,
        "user_ip6": retc.user_ip6,
        "user_ptr6": retc.user_ptr6,
        "server_ip6": retc.server_ip6,
        "server_mask6": retc.server_mask6,
        "learn_cmd": retc.learn_cmd,
        "user_ip": retc.user_ip,
        "user_ptr": retc.user_ptr,
        "ip_version": retc.ip_version,
        "script_type": retc.script_type,
        "user_auth": retc.user_auth,
        "user_auth_name": retc.user_auth_name,
        "user_auth_profiles": retc.user_auth_profiles,
        "user_password": retc.user_password,
        "response_file": retc.response_file,
    }


def _collect_swan_data(ctx: VpnContext) -> dict | None:
    is_swan = True
    pluto_verb = os.getenv("PLUTO_VERB")
    cmdline = tuple(sys.argv[1:]) if len(sys.argv) > 1 else tuple()
    instance = cmdline[0] if len(cmdline) > 0 else None

    # TODO: This method does not work in updown script
    # Need to get it done with vici listener daemon
    # userid          = _extract_dn_attr(
    #     _get_peer_dn(uniqueid = os.getenv("PLUTO_UNIQUEID")),
    #     ctx.cert_userid_field)
    # Lets use a stub for now:
    # ############ stub begins ########
    userid = None
    xauthid = os.getenv("PLUTO_XAUTH_ID")
    peerid = os.getenv("PLUTO_PEER_ID")
    sa_uid = os.getenv("PLUTO_UNIQUEID")
    if xauthid:
        if "=" in xauthid:
            userid = _extract_dn_attr(xauthid, ctx.cert_userid_field)
        else:
            userid = xauthid
    elif peerid:
        if "=" in peerid:
            userid = _extract_dn_attr(peerid, ctx.cert_userid_field)

    if not userid or (userid and "." in userid):
        userid = f"ipsec-{sa_uid}"
    # debug(ctx, f"{userid}  ==  {os.getenv('PLUTO_PEER_ID')}  ==  {os.getenv('PLUTO_XAUTH_ID')}")
    # ############ stub ends ########

    user_ip_txt = os.getenv("PLUTO_PEER_CLIENT") or "999"
    user_ip4_txt = os.getenv("PLUTO_PEER_SOURCEIP4_1") or "999"
    user_ip6_txt = os.getenv("PLUTO_PEER_SOURCEIP6_1") or "999"
    net_ip4_txt = os.getenv("SWAN_SERVER_NET4") or "999"
    net_ip6_txt = os.getenv("SWAN_SERVER_NET6") or "999"

    user_ip, user_ptr, ip_version = _parse_ipaddr(user_ip_txt)
    user_ip4, user_ptr4, _ = _parse_ipaddr(user_ip4_txt)
    user_ip6, user_ptr6, _ = _parse_ipaddr(user_ip6_txt)

    server_ip4 = None
    server_mask4 = None
    server_ip6 = None
    server_mask6 = None
    try:
        addr = ipaddress.ip_interface(net_ip4_txt)
        net = addr.network
        first_addr = next(iter(net.hosts()), None)
        if first_addr:
            first_addr = first_addr.exploded
        server_ip4 = str(first_addr)
        server_mask4 = str(net.netmask)
    # trunk-ignore(bandit/B110)
    except Exception:
        pass

    try:
        addr = ipaddress.ip_interface(net_ip6_txt)
        net = addr.network
        first_addr = next(iter(net.hosts()), None)
        if first_addr:
            first_addr = first_addr.exploded
        server_ip6 = str(first_addr)
        server_mask6 = str(net.netmask)
    # trunk-ignore(bandit/B110)
    except Exception:
        pass

    # linter type checking
    retc = VpnContext(
        is_swan=is_swan,
        pluto_verb=pluto_verb,
        instance=instance,
        cmdline=cmdline,
        userid=userid,
        user_ip4=user_ip4,
        user_ptr4=user_ptr4,
        server_ip4=server_ip4,
        server_mask4=server_mask4,
        user_ip6=user_ip6,
        user_ptr6=user_ptr6,
        server_ip6=server_ip6,
        server_mask6=server_mask6,
        user_ip=user_ip,
        user_ptr=user_ptr,
        ip_version=ip_version,
    )

    return {
        "is_swan": retc.is_swan,
        "pluto_verb": retc.pluto_verb,
        "instance": retc.instance,
        "cmdline": retc.cmdline,
        "userid": retc.userid,
        "user_ip4": retc.user_ip4,
        "user_ptr4": retc.user_ptr4,
        "server_ip4": retc.server_ip4,
        "server_mask4": retc.server_mask4,
        "user_ip6": retc.user_ip6,
        "user_ptr6": retc.user_ptr6,
        "server_ip6": retc.server_ip6,
        "server_mask6": retc.server_mask6,
        "user_ip": retc.user_ip,
        "user_ptr": retc.user_ptr,
        "ip_version": retc.ip_version,
    }


def _j2_replace(ctx: VpnContext, data: str) -> str:
    if ctx is None:
        return ""

    j2_vars = {}
    if ctx.server_ip4:
        j2_vars["VPN_SERVER_IP4"] = ctx.server_ip4
    if ctx.server_ip6:
        j2_vars["VPN_SERVER_IP6"] = ctx.server_ip6
    if ctx.dns_zone_name:
        j2_vars["VPN_DOMAIN"] = ctx.dns_zone_name

    env = Environment(undefined=StrictUndefined, autoescape=True)
    res = []
    for line in data.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        try:
            line = env.from_string(line).render(**j2_vars)
        except Exception:
            line = ""
        res.append(line)

    return "\n".join(res)


def _extract_dn_attr(dn: str | None, attr: str) -> str | None:
    if not dn or not attr:
        return None
    # pattern = r'(?i)\bCN\s*=\s*([^,\s]+)'
    pattern = rf"(?i)\b{re.escape(attr)}\s*=\s*([^,\s]+)"
    match = re.search(pattern, dn)
    return match.group(1) if match else None


def _knot_ctl() -> libknot.control.KnotCtl:
    ctl = libknot.control.KnotCtl()
    ctl.connect(KNOT_UNIX_SOCKET)
    ctl.set_timeout(5)
    return ctl


def _knot_close(ctl: libknot.control.KnotCtl):
    try:
        ctl.send(libknot.control.KnotCtlType.END)
        ctl.close()
    # trunk-ignore(bandit/B110)
    except Exception:
        pass


def _knot_silent_receive_block(ctl: libknot.control.KnotCtl):
    res = []
    try:
        res = ctl.receive_block()
    # trunk-ignore(bandit/B110)
    except Exception:
        pass
    return res


def _parse_user_auth_str(user_auth: str | None) -> tuple[str | None, tuple[str, ...]]:
    if not user_auth:
        return None, ()

    res = []
    parts = user_auth.split(",")
    for p in parts:
        p = p.strip()
        if len(p) > 0:
            res.append(p)

    if len(res) < 1:
        return None, ()
    return res[0], tuple(res[1:])


def _parse_ovpn_auth_file(file: str | None) -> tuple[str | None, ...]:
    if not file:
        return (None, None)

    cred_lines = None
    try:
        with open(file, "r", encoding="utf-8-sig") as f:
            cred_lines = f.readlines()
    except OSError:
        pass

    if cred_lines and len(cred_lines) > 1:
        return (cred_lines[0].rstrip("\r\n"), cred_lines[1].rstrip("\r\n"))

    return (None, None)


def _parse_ipaddr(ip: str | None) -> tuple[str | None, str | None, str | None]:
    """
    ip, ptr, version
    """
    if not ip:
        return (None, None, None)
    r_ip = None
    r_ptr = None
    r_ver = None
    try:
        addr = ipaddress.ip_interface(ip)
        r_ip = addr.network.network_address.exploded
        r_ptr = addr.network.network_address.reverse_pointer + "."
        r_ver = str(addr.version)
    # trunk-ignore(bandit/B110)
    except Exception:
        pass
    return (r_ip, r_ptr, r_ver)


def _parse_ipnetwork(
    net: str | None,
) -> tuple[str | None, str | None, str | None, str | None]:
    """
    net, mask, len, version
    """
    if not net:
        return (None, None, None, None)

    r_net = None
    r_mask = None
    r_len = None
    r_ver = None
    try:
        addr = ipaddress.ip_network(net)
        naddr = ipaddress.ip_address(addr.network_address)
        maddr = ipaddress.ip_address(addr.netmask)
        r_net = naddr.exploded
        r_mask = maddr.exploded
        r_len = str(addr.prefixlen)
        r_ver = str(addr.version)
    # trunk-ignore(bandit/B110)
    except Exception:
        pass

    return (r_net, r_mask, r_len, r_ver)


def ovpn_check_user_credentials(ctx: VpnContext) -> int:
    # TODO: check if using profiles is authorized
    if ctx is None or not ctx.user_auth_name:
        debug(ctx, "oAUTH. Cannot begin")
        return 1

    ### TODO: Check if user is authorized to use his profiles

    res = 1
    try:
        with open(ctx.auth_db_file, "r", encoding="utf-8-sig") as f:
            lnum = 0
            for line in f:
                lnum += 1
                user_line = line.strip(" \t\r\n")
                if not user_line:
                    continue
                if user_line.startswith("#"):
                    continue
                parts = user_line.split()
                if len(parts) < 2:
                    debug(
                        ctx,
                        f"oAUTH. Auth db is incorrect, skip the line {lnum}",
                        level=2,
                    )
                    continue

                db_login, db_password = parts[0], parts[1]
                if (
                    (db_login == ctx.user_auth_name or db_login == "*")
                    and
                    # trunk-ignore(bandit/B105)
                    (db_password == ctx.user_password or db_password == "*")
                ):
                    res = 0
    except OSError as err:
        debug(ctx, f"oAUTH. Cannot work with auth db: {err}")
        return 1

    return res


def ovpn_client_connect(ctx: VpnContext) -> int:
    if ctx is None or not ctx.response_file or not ctx.user_auth_name or not ctx.userid:
        debug(ctx, "oCONNECT. Cannot begin")
        return 1

    if not ctx.user_auth_profiles:
        return 0

    for profile in ctx.user_auth_profiles:
        if not profile:
            continue
        profile_dir = os.path.join(ctx.profiles_db_dir, profile)
        if not os.path.isdir(profile_dir):
            continue

        userid_file = os.path.join(profile_dir, f"{ctx.userid}.conf")
        default_file = os.path.join(profile_dir, "DEFAULT.conf")

        pick_config = None
        if os.path.isfile(userid_file):
            pick_config = userid_file
        elif os.path.isfile(default_file):
            pick_config = default_file

        if pick_config:
            copy_data = None
            try:
                with open(pick_config, "r", encoding="utf-8-sig") as f:
                    copy_data = f.read()
            except OSError as err:
                debug(ctx, f"oCONNECT. Cant read config file {pick_config} {err}")
                return 1

            if not copy_data:
                continue

            copy_data = _j2_replace(ctx, copy_data)

            if not copy_data:
                continue

            try:
                with open(ctx.response_file, "a+", encoding="utf-8") as f:
                    f.write(copy_data)
            except OSError as err:
                debug(ctx, f"oCONNECT. Cant write response config {err}")
                return 1
    return 0


def learn_address(ctx: VpnContext) -> int:
    if ctx is None:
        debug(ctx, "LEARN. Cannot begin")
        return 1

    # debug(ctx, ctx.to_json())

    res = 0
    if (
        ctx.is_ovpn
        and ctx.learn_cmd
        and (ctx.learn_cmd == "add" or ctx.learn_cmd == "update")
    ) or (ctx.is_swan and ctx.pluto_verb and (ctx.pluto_verb.startswith("up-client"))):
        # ADD
        # res += firewall_clean_rules(ctx)
        firewall_clean_rules(ctx)
        dns_delete_by_ip(ctx)
        if ctx.is_ovpn:
            res += ovpn_firewall_apply_rules(ctx)
        elif ctx.is_swan:
            res += swan_firewall_apply_rules(ctx)
        res += dns_add_client(ctx)
        if res > 0:
            firewall_clean_rules(ctx)
            dns_delete_by_ip(ctx)
    elif (
        ctx.is_ovpn
        and ctx.learn_cmd
        and (ctx.learn_cmd == "del" or ctx.learn_cmd == "delete")
    ) or (
        ctx.is_swan and ctx.pluto_verb and (ctx.pluto_verb.startswith("down-client"))
    ):
        # DELETE
        res += firewall_clean_rules(ctx)
        res += dns_delete_by_ip(ctx)
    else:
        # UNKNOWN
        debug(
            ctx,
            f"LEARN. Unknown command. {ctx.learn_cmd or ctx.pluto_verb} for {ctx.userid}",
        )
        return 1

    if res > 0:
        debug(ctx, f"LEARN. Failed {ctx.learn_cmd or ctx.pluto_verb } for {ctx.userid}")

    return res


def _dict_encode(data: dict) -> str:
    res = ""
    try:
        json_str = json.dumps(data, ensure_ascii=False, separators=(",", ":"))
        res = base64.b64encode(json_str.encode("utf-8")).decode("ascii")
    # trunk-ignore(bandit/B110)
    except Exception:
        pass
    return res


def _dict_decode(encoded: str) -> dict:
    res = {}
    try:
        json_str = base64.b64decode(encoded.encode("ascii")).decode("utf-8")
        res = json.loads(json_str)
    # trunk-ignore(bandit/B110)
    except Exception:
        pass
    return res


def dns_add_client(ctx: VpnContext) -> int:
    if (
        ctx is None
        or not ctx.dns_zone_name
        or not ctx.user_ip
        or not ctx.user_ptr
        or not ctx.ip_version
        or not ctx.userid
    ):
        debug(ctx, "DNS. Add: Cannot begin")
        return 1

    
    client_from = "unknown"
    if ctx.is_ovpn:
        client_from = "ovpn"
    elif ctx.is_swan:
        client_from = "swan"

    if ctx.instance:
        # client_from = f"{client_from}-{ctx.instance}"
        client_from = ctx.instance

    client_text = _dict_encode({
        "ts":       datetime.now(ZoneInfo("UTC")).isoformat(),
        "source":   client_from
    })

    client_dns = f"{ctx.userid}{ctx.dns_client_suffix}.{ctx.dns_zone_name}."
    addr_type = "A" if ctx.ip_version == "4" else "AAAA"
    res = 0
    try:
        ctl = _knot_ctl()
    except Exception as err:
        debug(ctx, f"DNS. Add: Cannot open control socket: {err}")
        return 1

    try:
        ctl.send_block(cmd="zone-begin")
        _knot_silent_receive_block(ctl)

        ctl.send_block(
            cmd="zone-set",
            owner=client_dns,
            rtype=addr_type,
            data=ctx.user_ip,
            ttl=ctx.dns_client_ttl,
        )
        _knot_silent_receive_block(ctl)

        ctl.send_block(
            cmd="zone-set",
            owner=ctx.user_ptr,
            rtype="PTR",
            data=client_dns,
            ttl=ctx.dns_client_ttl,
        )
        _knot_silent_receive_block(ctl)

        ctl.send_block(
            cmd="zone-set",
            owner=ctx.user_ptr,
            rtype="TXT",
            data=client_text,
            ttl=ctx.dns_client_ttl,
        )
        _knot_silent_receive_block(ctl)

        ctl.send_block(cmd="zone-commit")
        _knot_silent_receive_block(ctl)

        #### VERIFY
        ctl.send_block(cmd="zone-read")
        resp = _knot_silent_receive_block(ctl)

        number_of_records_to_add = 3
        matches = 0
        # debug(ctx, json.dumps(resp, indent=4))
        for the_zone in resp:
            for the_owner in resp[the_zone]:
                for the_type in resp[the_zone][the_owner]:
                    the_data_array = (
                        resp[the_zone][the_owner][the_type].get("data") or []
                    )
                    for the_data in the_data_array:
                        # debug(ctx, f">>> {the_owner}  {the_type}  {the_data}")

                        ip_addr_exploded, _, _ = _parse_ipaddr(the_data)
                        if (
                            (
                                the_owner == client_dns
                                and the_type == addr_type
                                and ip_addr_exploded == ctx.user_ip
                            )
                            or (
                                the_owner == ctx.user_ptr
                                and the_type == "PTR"
                                and the_data == client_dns
                            )
                            or (
                                the_owner == ctx.user_ptr
                                and the_type == "TXT"
                                and the_data.strip('"') == client_text
                            )
                        ):
                            matches += 1

        if matches != number_of_records_to_add:
            debug(
                ctx,
                f"DNS. Add: Cannot add all {number_of_records_to_add} records, got only {matches}",
            )
            res = 1

    except Exception as err:
        ctl.send_block(cmd="zone-abort")
        debug(ctx, f"DNS. Add: Command sequence error: {err}")
        res = 1

    _knot_close(ctl)

    return res


def dns_delete_by_ip(ctx: VpnContext) -> int:
    if ctx is None or not ctx.user_ip or not ctx.user_ptr or not ctx.ip_version:
        debug(ctx, "DNS. Delete: Cannot begin")
        return 1

    addr_type = "A" if ctx.ip_version == "4" else "AAAA"
    res = 0
    try:
        ctl = _knot_ctl()
    except Exception as err:
        debug(ctx, f"DNS. Delete: Cannot open control socket: {err}")
        return 1

    try:
        ctl.send_block(cmd="zone-read")
        resp = _knot_silent_receive_block(ctl)

        ctl.send_block(cmd="zone-begin")
        _knot_silent_receive_block(ctl)

        # debug(json.dumps(resp, indent=4))
        changing_the_zone = False
        for the_zone in resp:
            for the_owner in resp[the_zone]:
                for the_type in resp[the_zone][the_owner]:
                    the_data_array = (
                        resp[the_zone][the_owner][the_type].get("data") or []
                    )
                    for the_data in the_data_array:
                        # debug(f"{the_owner}  {the_type}  {the_data}")
                        if the_owner == ctx.user_ptr:
                            if the_type == "TXT" or the_type == "PTR":
                                changing_the_zone = True
                                ctl.send_block(
                                    cmd="zone-unset",
                                    zone=the_zone,
                                    owner=ctx.user_ptr,
                                    rtype=the_type,
                                )
                                _knot_silent_receive_block(ctl)

                            if the_type == "PTR":
                                changing_the_zone = True
                                ctl.send_block(
                                    cmd="zone-unset",
                                    owner=the_data,
                                    rtype=addr_type,
                                )
                                _knot_silent_receive_block(ctl)

        if changing_the_zone:
            ctl.send_block(cmd="zone-commit")
        else:
            ctl.send_block(cmd="zone-abort")
        _knot_silent_receive_block(ctl)

    except Exception as err:
        ctl.send_block(cmd="zone-abort")
        debug(ctx, f"DNS. Delete: Command sequence error: {err}")
        res = 1

    _knot_close(ctl)

    return res


def firewall_clean_rules(ctx: VpnContext) -> int:
    if ctx is None or not ctx.user_ip:
        debug(ctx, "FIREWALL. Clean: Cannot begin")
        return 1

    nft = NftManager()
    p = "unknown"
    if ctx.is_ovpn:
        p = "ovpn"
    elif ctx.is_swan:
        p = "swan"
    tag = f"{p}-{ctx.user_ip}"
    return nft.delete_by_tag(tag=tag)


def ovpn_firewall_apply_rules(ctx: VpnContext) -> int:

    if (
        ctx is None
        or not ctx.is_ovpn
        or not ctx.user_ip
        or not ctx.ip_version
        or not ctx.userid
    ):
        debug(ctx, "oFIREWALL. Cannot begin")
        return 1

    if not ctx.user_auth_name or not ctx.user_auth_profiles:
        return 0

    p = "unknown"
    if ctx.is_ovpn:
        p = "ovpn"
    elif ctx.is_swan:
        p = "swan"
    tag = f"{p}-{ctx.user_ip}"

    res = 0
    for profile in ctx.user_auth_profiles:
        profile_dir = os.path.join(ctx.profiles_db_dir, profile)
        if not os.path.isdir(profile_dir):
            continue

        userid_file = os.path.join(profile_dir, f"{ctx.userid}.fwl")
        default_file = os.path.join(profile_dir, "DEFAULT.fwl")

        pick_config = None
        if os.path.isfile(userid_file):
            pick_config = userid_file
        elif os.path.isfile(default_file):
            pick_config = default_file

        if pick_config is not None:
            try:
                with open(pick_config, "r", encoding="utf-8-sig") as rules:
                    for rule_line in rules:
                        rule_line = rule_line.strip()
                        if not rule_line or rule_line.startswith("#"):
                            continue

                        parts = rule_line.split()
                        rule_name = parts[0] if len(parts) > 0 else ""
                        rule_p1 = parts[1] if len(parts) > 1 else ""
                        nft = NftManager()

                        # NAT
                        # NAT4
                        # NAT6
                        # ALLOWNET net/mask
                        # ALLOWNET "inet"
                        r = 0
                        match rule_name.upper():
                            case "NAT":
                                r = nft.add_masquerade(
                                    tag=tag,
                                    user_ip=ctx.user_ip,
                                    ip_version=ctx.ip_version,
                                )
                                res += r
                            case "NAT4":
                                if ctx.ip_version == "4":
                                    r = nft.add_masquerade(
                                        tag=tag,
                                        user_ip=ctx.user_ip,
                                        ip_version=ctx.ip_version,
                                    )
                                    res += r
                            case "NAT6":
                                if ctx.ip_version == "6":
                                    r = nft.add_masquerade(
                                        tag=tag,
                                        user_ip=ctx.user_ip,
                                        ip_version=ctx.ip_version,
                                    )
                                    res += r
                            case "ALLOWNET":
                                match rule_p1.upper():
                                    case "INET" | "INTERNET":
                                        r = nft.add_internet_access(
                                            tag=tag,
                                            user_ip=ctx.user_ip,
                                            ip_version=ctx.ip_version,
                                        )
                                    case _:
                                        r_net, r_mask, r_len, r_ver = _parse_ipnetwork(
                                            rule_p1
                                        )
                                        if not r_net or not r_len or not r_ver:
                                            r = 1
                                        elif ctx.ip_version == r_ver:
                                            r = nft.add_subnet_access(
                                                tag=tag,
                                                user_ip=ctx.user_ip,
                                                ip_version=ctx.ip_version,
                                                net_addr=r_net,
                                                net_len=r_len,
                                            )
                                res += r
                            case _:
                                debug(
                                    ctx,
                                    f"oFIREWALL. Unknown rule {rule_name} in file {pick_config}",
                                )
                        if r != 0:
                            debug(
                                ctx,
                                f"oFIREWALL. Cannot apply rule {rule_name} {rule_p1} for {ctx.user_ip} from file {pick_config}",
                            )

            except OSError:
                debug(ctx, f"oFIREWALL. Cannot work with config {pick_config}")
                return 1

    return res


def swan_firewall_apply_rules(ctx: VpnContext) -> int:

    if ctx is None or not ctx.is_swan or not ctx.user_ip or not ctx.ip_version:
        debug(ctx, "sFIREWALL. Cannot begin")
        return 1

    p = "unknown"
    if ctx.is_ovpn:
        p = "ovpn"
    elif ctx.is_swan:
        p = "swan"
    tag = f"{p}-{ctx.user_ip}"

    nft = NftManager()
    res = 0

    res += nft.add_masquerade(tag=tag, user_ip=ctx.user_ip, ip_version=ctx.ip_version)
    res += nft.add_full_access(tag=tag, user_ip=ctx.user_ip, ip_version=ctx.ip_version)

    if res != 0:
        debug(ctx, f"sFIREWALL. Cannot apply rules for ipsec ({ctx.user_ip})")

    return res


def main() -> int:
    ctx = VpnContext(debug_level=3)
    if (
        not ctx.auth_db_file
        or not ctx.profiles_db_dir
        or not ctx.knot_socket_file
        or not os.path.isfile(ctx.auth_db_file)
        or not os.path.isdir(ctx.profiles_db_dir)
        or not os.path.exists(ctx.knot_socket_file)
        or not ctx.cert_userid_field
    ):
        debug(ctx, "MAIN. Cannot begin")
        return 1

    ctx = replace(
        ctx,
        **(_var_read_dns_zone_name(ctx) or {}),
    )
    ovpn_script_type = os.getenv("script_type")
    ipsec_pluto_verb = os.getenv("PLUTO_VERB")

    if ovpn_script_type:
        # called by openvpn

        ctx = replace(ctx, **(_collect_ovpn_data(ctx) or {}))
        match ovpn_script_type:
            case "user-pass-verify":
                res = ovpn_check_user_credentials(ctx)
                if res != 0:
                    debug(ctx, f"MAIN. {ovpn_script_type} failed for {ctx.userid}")
                return res

            case "client-connect":
                res = ovpn_client_connect(ctx)
                if res != 0:
                    debug(ctx, f"MAIN. {ovpn_script_type} failed for {ctx.userid}")
                return res

            case "learn-address":
                res = learn_address(ctx)
                if res != 0:
                    debug(ctx, f"MAIN. {ovpn_script_type} failed for {ctx.userid}")
                return res
            case _:
                debug(ctx, f"MAIN. Unknown ovpn script: {ovpn_script_type}")
                return 1
    elif ipsec_pluto_verb:
        # called by strongswan

        ctx = replace(ctx, **(_collect_swan_data(ctx) or {}))

        if ipsec_pluto_verb.startswith("up-client") or ipsec_pluto_verb.startswith(
            "down-client"
        ):
            res = learn_address(ctx)
            if res != 0:
                debug(ctx, f"MAIN. {ipsec_pluto_verb} failed for {ctx.userid}")
            return res

    #     debug(ctx, str(swan))
    else:
        debug(ctx, "MAIN. Unknown mode.")
        return 1

    debug(ctx, "Im lost.")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
