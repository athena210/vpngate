#!/bin/sh -e

echo "============="

export VPN_DNS_ZONE_SERIAL="${VPN_DNS_ZONE_SERIAL:-1}"

chown -R knot:knot /var/lib/knot /run/knot

echo "$VPN_DNS_ZONE" > "/VPN_DNS_ZONE"
if [ -z "$VPN_DNS_ZONE" ] ; then
    echo "Var VPN_DNS_ZONE is empty. exit"
    exit 1
fi

echo "Processing supervisord config"
jinjanate /wconf/supervisord.conf.j2 -o /supervisord.conf --undefined
chmod 644 /supervisord.conf

echo "Processing KNOT dns config"
jinjanate /wconf/knot.conf.j2 -o /etc/knot/knot.conf --undefined --filter /etc/vpn/j2filter.py
chmod 644 /etc/knot/knot.conf

echo "Processing KNOT split config"
jinjanate /wconf/knot-split.conf.j2 -o /etc/knot/knot-split.conf --undefined --filter /etc/vpn/j2filter.py
chmod 644 /etc/knot/knot-split.conf

echo "Processing KNOT main zone config"
jinjanate /wconf/zone-main.j2 -o /var/lib/knot/main.zone --undefined --filter /etc/vpn/j2filter.py
chmod 644 /var/lib/knot/main.zone

echo "Starting firewall"
/firewall.nft

# strongswan
if { [ -n "$SWAN_SERVER_NET4" ] || [ -n "$SWAN_SERVER_NET6" ]; } && [ -n "$PUBLIC_DNS_NAME" ] ; then
    echo "Strongswan is configured"
    echo "Adding dummy interface"
    ip link add ikev2s type dummy
    ip link set ikev2s up

    TMPFILE=$(mktemp) || exit 1

    if [ -n "$SWAN_SERVER_NET4" ] ; then
        echo "IPV4"
        # echo "{{ SWAN_SERVER_NET4 | iplib_first_addr_with_netlen }}" > "$TMPFILE"
        echo "{{ SWAN_SERVER_NET4 | iplib_first_addr }}/32" > "$TMPFILE"
        ifaddr="$(jinjanate "$TMPFILE" --undefined --filter /etc/vpn/j2filter.py)"
        [ -n "$ifaddr" ] || exit 1
        echo "Setting $ifaddr for dummy interface"
        ip addr add "$ifaddr" dev ikev2s

        echo "Processing KNOT ptr zone for swan_server"
        export VPN_NETWORK="$SWAN_SERVER_NET4"
        jinjanate /wconf/zone-ptr.j2 -o /var/lib/knot/swan-server.ptr4.zone --undefined --filter /etc/vpn/j2filter.py
        chmod 644 /var/lib/knot/swan-server.ptr4.zone

        echo "Adding vpn net to firewall"
        nft add element inet my_firewall allowed_nets4 { "$SWAN_SERVER_NET4" }
    fi

    if [ -n "$SWAN_SERVER_NET6" ] ; then
        echo "IPV6"
        echo "{{ SWAN_SERVER_NET6 | iplib_first_addr_with_netlen }}" > "$TMPFILE"
        # echo "{{ SWAN_SERVER_NET6 | iplib_first_addr }}/128" > "$TMPFILE"
        ifaddr="$(jinjanate "$TMPFILE" --undefined --filter /etc/vpn/j2filter.py)"
        echo "Setting $ifaddr for dummy interface"
        [ -n "$ifaddr" ] || exit 1
        echo "Setting $ifaddr for dummy interface"
        ip -6 addr add "$ifaddr" dev ikev2s
        # ip -6 route add default via fd7a:c506:d79a:4::1

        echo "Processing KNOT ptr6 zone for swan_server"
        export VPN_NETWORK="$SWAN_SERVER_NET6"
        jinjanate /wconf/zone-ptr.j2 -o /var/lib/knot/swan-server.ptr6.zone --undefined --filter /etc/vpn/j2filter.py
        chmod 644 /var/lib/knot/swan-server.ptr6.zone

        echo "Adding vpn net to firewall"
        nft add element inet my_firewall allowed_nets6 { "$SWAN_SERVER_NET6" }
    fi

    rm -f "$TMPFILE"
    echo "Processing swanctl config"
    jinjanate /wconf/swanctl.conf.j2 -o /etc/swanctl/swanctl.conf --undefined --filter /etc/vpn/j2filter.py
    chmod 644 /etc/swanctl/swanctl.conf

    echo "Processing swanctl updown script"
    jinjanate /wconf/updown.sh.j2 -o /etc/vpn/updown.sh --undefined --filter /etc/vpn/j2filter.py
    chmod 755 /etc/vpn/updown.sh

fi


# ovpn strong. Cannot work without ipv4
if [ -n "$OVPN_STRONG_NET4" ] && [ -n "$PUBLIC_STRONG_PORT" ] ; then
    echo "Ovpn strong is configured"

    echo "Adding ovpn strong port to firewall"
    nft add element inet my_firewall public_ports_tcp { "$PUBLIC_STRONG_PORT" }

    echo "Adding ovpn strong net4 to firewall"
    nft add element inet my_firewall allowed_nets4 { "$OVPN_STRONG_NET4" }

    echo "Processing ovpn-strong config"
    jinjanate /wconf/server-strong.conf.j2 -o /etc/vpn/server-strong.conf --undefined --filter /etc/vpn/j2filter.py
    chmod 644 /etc/vpn/server-strong.conf

    echo "Processing KNOT ptr zone for ovpn_strong"
    export VPN_NETWORK="$OVPN_STRONG_NET4"
    jinjanate /wconf/zone-ptr.j2 -o /var/lib/knot/ovpn-strong.ptr4.zone --undefined --filter /etc/vpn/j2filter.py
    chmod 644 /var/lib/knot/ovpn-strong.ptr4.zone

    if [ -n "$OVPN_STRONG_NET6" ] ; then
        echo "Processing KNOT ptr6 zone for ovpn_strong"
        export VPN_NETWORK="$OVPN_STRONG_NET6"
        jinjanate /wconf/zone-ptr.j2 -o /var/lib/knot/ovpn-strong.ptr6.zone --undefined --filter /etc/vpn/j2filter.py
        chmod 644 /var/lib/knot/ovpn-strong.ptr6.zone

        echo "Adding ovpn strong net6 to firewall"
        nft add element inet my_firewall allowed_nets6 { "$OVPN_STRONG_NET6" }
    fi
fi


# ovpn compat. Cannot work without ipv4
if [ -n "$OVPN_COMPAT_NET4" ] && [ -n "$PUBLIC_COMPAT_PORT" ] ; then
    echo "Ovpn compat is configured"

    echo "Adding ovpn compat port to firewall"
    nft add element inet my_firewall public_ports_tcp { "$PUBLIC_COMPAT_PORT" }

    echo "Adding ovpn compat net4 to firewall"
    nft add element inet my_firewall allowed_nets4 { "$OVPN_COMPAT_NET4" }

    echo "Processing ovpn-compat config"
    jinjanate /wconf/server-compat.conf.j2 -o /etc/vpn/server-compat.conf --undefined --filter /etc/vpn/j2filter.py
    chmod 644 /etc/vpn/server-compat.conf

    echo "Processing KNOT ptr zone for ovpn_compat"
    export VPN_NETWORK="$OVPN_COMPAT_NET4"
    jinjanate /wconf/zone-ptr.j2 -o /var/lib/knot/ovpn-compat.ptr4.zone --undefined --filter /etc/vpn/j2filter.py
    chmod 644 /var/lib/knot/ovpn-compat.ptr4.zone

    if [ -n "$OVPN_COMPAT_NET6" ] ; then
        echo "Processing KNOT ptr6 zone for ovpn_compat"
        export VPN_NETWORK="$OVPN_COMPAT_NET6"
        jinjanate /wconf/zone-ptr.j2 -o /var/lib/knot/ovpn-compat.ptr6.zone --undefined --filter /etc/vpn/j2filter.py
        chmod 644 /var/lib/knot/ovpn-compat.ptr6.zone

        echo "Adding ovpn compat net6 to firewall"
        nft add element inet my_firewall allowed_nets6 { "$OVPN_COMPAT_NET6" }
    fi
fi


echo "Starting supervisor"
exec /usr/bin/supervisord -c /supervisord.conf

echo "==========Container shutdown==============="
# sleep inf
