#!/bin/bash

WD="server_vpn"
IMAGE_NAME="server_vpn"
IMAGE_TAG="${1:-1}"

if [ -z "$IMAGE_TAG" ] ; then
    echo "Usage:"
    echo "  $0 <IMAGE_TAG>"
    echo "Example - build vpn server version 1:"
    echo "  $0 1"
    echo
    exit 1
fi


docker build -t "$IMAGE_NAME:$IMAGE_TAG" \
    --build-arg WD="$WD" \
    --build-arg IMAGE_NAME="$IMAGE_NAME" \
    --build-arg IMAGE_TAG="$IMAGE_TAG" \
    -f "$WD/Dockerfile" \
    . \
&& \
echo
docker save "$IMAGE_NAME:$IMAGE_TAG" -o ../images_backup/"${IMAGE_NAME}:${IMAGE_TAG}:$(date '+%y%m%d%H%M%S')".tar
