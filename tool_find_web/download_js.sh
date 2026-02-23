#!/bin/bash

URL_FILE="urls.txt"
OUT_DIR="js"
UA="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0 Safari/537.36"

mkdir -p "$OUT_DIR"

while read -r url; do
    [ -z "$url" ] && continue

    # 取 URL 最后的文件名
    filename=$(basename "$url")

    echo "[+] Downloading $filename"

    curl -k -s -L \
        -A "$UA" \
        --connect-timeout 10 \
        --max-time 30 \
        -o "$OUT_DIR/$filename" \
        -w "status=%{http_code} size=%{size_download}\n" \
        "$url"

done < "$URL_FILE"

