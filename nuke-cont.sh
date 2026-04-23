#!/bin/bash

IMAGE_NAME="low-round-psu:latest"

# Get container IDs for the specified image name
CONTAINER_IDS=$(sudo docker ps -q --filter "ancestor=$IMAGE_NAME")

# Check if there are any containers to kill
if [ -n "$CONTAINER_IDS" ]; then
    # Kill the containers
    sudo docker kill $CONTAINER_IDS
    echo "Killed containers running image: $IMAGE_NAME"
else
    echo "No containers found running image: $IMAGE_NAME"
fi