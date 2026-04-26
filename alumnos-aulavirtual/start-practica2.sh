#!/bin/sh
docker compose down --remove-orphans -v
docker compose pull
docker compose up

