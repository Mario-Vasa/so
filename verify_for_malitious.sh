#!/bin/bash

# Verifică dacă a fost dat un fișier și un director ca argument
if [ "$#" -ne 2 ]; then
    echo "Usage: $0 <file> <destination_directory>"
    exit 1
fi

# Obțineți numele fișierului și directorul de destinație
file=$1
dest_dir=$2

# Verifică dacă fișierul există
if [ ! -f "$file" ]; then
    echo "File not found: $file"
    exit 1
fi

# Verifică dacă directorul de destinație există
if [ ! -d "$dest_dir" ]; then
    echo "Destination directory not found: $dest_dir"
    exit 1
fi

# Acordă toate permisiunile fișierului
chmod 777 "$file"

# Obțineți numărul de linii, cuvinte și caractere
lines=$(wc -l < "$file")
words=$(wc -w < "$file")
chars=$(wc -m < "$file")

# Verificați criteriile suspecte
is_suspect=0

if [ "$lines" -lt 3 ] && [ "$words" -gt 1000 ] && [ "$chars" -gt 2000 ]; then
    is_suspect=1
fi

if LC_ALL=C grep -q '[^[:print:]]' "$file"; then
    is_suspect=1
fi

keywords=('risk' 'attack' 'malitios')

# Iterează peste cuvintele cheie
for keyword in "${keywords[@]}"; do
    # Verifică dacă cuvântul cheie este în fișier
    if grep -qi "$keyword" "$file"; then
        # Setează is_suspect la 1 dacă este găsit cuvântul cheie
        is_suspect=1
        break  # Iese din bucla
    fi
done

# Restrictioneaza permisiunile fișierului
chmod 000 "$file"

# Mută fișierul dacă este suspect sau afișează "SAFE"
if [ "$is_suspect" -eq 1 ]; then
    # Mută fișierul în directorul de destinație
    mv "$file" "$dest_dir"
    echo "Moved to: $file"
else
    echo "SAFE"
fi
