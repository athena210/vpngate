FROM alpine:3.23

ARG \
    WD=none \
    IMAGE_NAME=none \
    IMAGE_TAG=none


RUN \
    apk --no-cache add  \
        ca-certificates \
        tzdata \
        curl \
        supervisor \
        openvpn \
        knot \
        knot-mod-geoip \
        knot-utils \
        nftables \
        nginx \
        strongswan \
        python3 \
        py3-pip &&\
    pip install pydantic jinjanator pip-nftables libknot flask --break-system-packages &&\
    apk del py3-pip


COPY ${WD}/entrypoint.sh ${WD}/firewall.nft /

COPY ${WD}/helper.py ${WD}/j2filter.py /etc/vpn/

COPY ${WD}/wconf/ /wconf

COPY ${WD}/nginx.conf /etc/

COPY ${WD}/flask/ /flask

COPY ${WD}/charon.conf /etc/strongswan.d

RUN \
    chmod +x /entrypoint.sh /firewall.nft ; \
    mkdir -p \
        /vpn/ovpn \
        /vpn/sswan \
        /pki \
        /vpnstat \
        /run/knot \
        /var/lib/knot ; \
    ln -nsf /pki/ca.crt /etc/swanctl/x509ca/ca.crt ; \
    ln -nsf /pki/crl.pem /etc/swanctl/x509crl/crl.pem ; \
    ln -nsf /pki/server.crt /etc/swanctl/x509/server.crt ; \
    ln -nsf /pki/server.key /etc/swanctl/private/server.key

ENTRYPOINT ["/entrypoint.sh"]

# HEALTHCHECK --interval=5s --timeout=3s --start-period=10s --retries=3 \
#   CMD pgrep -f openvpn || exit 1

LABEL \
    IMAGE_NAME=${IMAGE_NAME} \
    IMAGE_TAG=${IMAGE_TAG}
