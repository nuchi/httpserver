#!/bin/bash

IMAGE="/Users/haggai/tripleByte/httpserver/www/images/cat.jpg"

HEADER="Content-type: image/jpeg"

printf %s\\r\\n\\r\\n "$HEADER"

cat "$IMAGE"