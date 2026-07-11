#!/usr/bin/env python3

from __future__ import annotations

from datetime import datetime
from threading import Lock
from time import monotonic
from zoneinfo import ZoneInfo
import json
import base64
import ipaddress
import logging
from dataclasses import asdict, dataclass, field, replace
from flask import Flask, abort, request, make_response, render_template
import libknot.control


DNS_CACHE_TTL       = 5
DNS_ZONE_NAME_FILE  = "/VPN_DNS_ZONE"
KNOT_UNIX_SOCKET    = "/run/knot/knot.sock"
BASE_PATH           = "/"


@dataclass(frozen=True, slots=True, kw_only=True)
class ZoneRecord:
    name: str       = ""
    type: str       = ""
    addr: str       = ""
    source: str     = ""
    ts: str|None    = None


class ZoneCache:
    def __init__(self, ttl=DNS_CACHE_TTL):
        self.ttl                    = ttl
        self.lock                   = Lock()
        self.data: list[ZoneRecord] = []
        self.last_success           = None
        self.last_update_monotonic  = 0

    def expired(self) -> bool:
        return (monotonic() - self.last_update_monotonic) >= self.ttl

    def load_from_knot(self) -> list[ZoneRecord]:
        data = []
        selected = []

        try:
            ctl = _knot_ctl()
        except Exception as err:
            log.error(f"DNS. Add: Cannot open control socket: {err}")
            return data

        try:
            ctl.send_block(cmd="zone-read")
            resp = _knot_silent_receive_block(ctl)
            for the_zone in resp:
                for the_owner in resp[the_zone]:
                    for the_type in resp[the_zone][the_owner]:
                        the_data_array = (
                            resp[the_zone][the_owner][the_type].get("data") or []
                        )
                        for the_data in the_data_array:
                            if the_type in ("A", "AAAA", "TXT"):
                                selected.append((the_owner, the_type, the_data))
        except Exception:
            ctl.send_block(cmd="zone-abort")
        finally:
            _knot_close(ctl)

        exclude_names = (
            f"{vpn_zone_name}.",
            f"ns.{vpn_zone_name}.",
            f"{vpn_zone_name}.{vpn_zone_name}."
        )

        for (the_owner, the_type, the_data) in selected:
            if (
                the_type not in ("A", "AAAA") or
                the_owner in exclude_names
            ):
                continue

            _, ptr, _ = _parse_ipaddr(the_data)
            for (s_owner, s_type, s_data) in selected:
                if (
                    s_owner == ptr and
                    s_type == "TXT"
                ):
                    # log.info(f"=== {the_owner}  {the_type}  {the_data}  {the_source}")
                    ext_data = _dict_decode(s_data.strip('"'))
                    data.append( ZoneRecord(
                        name    = the_owner,
                        type    = the_type,
                        addr    = the_data,
                        source  = ext_data.get("source", "unknown"),
                        ts      = ext_data.get("ts")
                    ))
        # log.info(f"=== {len(data)}")
        return data

    def refresh(self) -> None:
        new_data                    = self.load_from_knot()
        self.data                   = new_data
        self.last_success           = datetime.now(ZoneInfo("UTC"))
        self.last_update_monotonic  = monotonic()

    def get(self) -> list[ZoneRecord]:
        if not self.expired():
            return self.data

        with self.lock:
            if self.expired():
                log.info("Refreshing cache")
                self.refresh()

        return self.data


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


def _var_read_dns_zone_name() -> str | None:
    if not DNS_ZONE_NAME_FILE:
        log.error("Var file name has not been set.")
        return None

    dns_zone_name = None
    try:
        with open(DNS_ZONE_NAME_FILE, "r", encoding="utf-8-sig") as f:
            dns_zone_name = f.read().strip()
    except OSError:
        log.error(f"Cant read var file: {DNS_ZONE_NAME_FILE}")
        return None

    if not dns_zone_name:
        log.error("DNS zone name is empty.")
        return None

    return dns_zone_name


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


def web_route_index() -> str:
    data = []
    try:
        data = cache.get()
    except Exception as e:
        log.error("Cannot update cache")
        abort(
            500,
            description=f"Cannot update cache: {e}"
        )

    ts = cache.last_success.isoformat() if cache.last_success is not None else None
    web_table = None
    if len(data) > 0:
        web_table = """<tr class="table_header">
<th>NAME</th>
<th>ADDR</th>
<th>SERVER</th>
<th>TIME</th>
</tr>"""

    i = 0
    for rec in data:
        i += 1
        row_class = "table_row1" if i % 2 == 0 else "table_row2"
        web_table = f"""{web_table}<tr class="{row_class}">
<td>{rec.name.rstrip(".")}</td>
<td>{rec.addr}</td>
<td>{rec.source}</td>
<td class="iso-time">{rec.ts}</td>
</tr>"""

    response = make_response(
        render_template(
            "web_index.html",
            WEB_DNS_TS      = ts,
            WEB_VPN_ZONE    = vpn_zone_name,
            WEB_TABLE       = web_table,
        )
    )
    response.headers["Cache-Control"] = (
        "no-store, no-cache, must-revalidate, "
        "max-age=0, private"
    )
    response.headers["Pragma"] = "no-cache"
    response.headers["Expires"] = "0"
    return response


# GLOBAL
app = Flask(__name__)
app.add_url_rule(BASE_PATH, view_func=web_route_index)
vpn_zone_name = _var_read_dns_zone_name()
cache = ZoneCache()
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s"
)
log = logging.getLogger(__name__)

if __name__ == "__main__":
    app.run()
