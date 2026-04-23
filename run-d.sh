#!/bin/bash

sudo docker run -d --rm \
    -v $(pwd)/src:/home/ubuntu/src \
    --cap-add=NET_ADMIN \
    low-round-psu:latest \
    tail -f /dev/null
