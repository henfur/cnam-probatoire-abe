#!/bin/bash

podman run -d -p 13306:3306 -e "MARIADB_ROOT_PASSWORD=changeit" mariadb:10.6
diesel migration run
