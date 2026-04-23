#!/bin/bash 

image_name="low-round-psu:latest"

container_id=$(sudo docker ps --filter "ancestor=$image_name" --format "{{.ID}}")

echo "Container ID: $container_id"

if [ -z "$container_id" ]; then
    echo "No running container found for image: $image_name"
    exit 1
fi

sudo docker exec -it "$container_id" /bin/bash