#!/bin/bash
docker build -t htb_blinded .
docker run --privileged -p1337:1337 -it htb_blinded
