#!/bin/bash

sudo docker run -it --rm \
    --privileged \
    -v $(pwd)/src:/home/ubuntu/src \
    --cap-add=NET_ADMIN \
    low-round-psu:latest \
    bash