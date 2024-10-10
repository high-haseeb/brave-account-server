#!/bin/sh

curl -X POST localhost:6969/user/reset \
  -H "Content-Type: application/json" \
  -d '{
        "email": "haseebkhalidoriginal@gmail.com"
      }'
