#!/bin/bash

if [ "$EUID" -ne 0 ]; then 
  echo "Please re-run this script as root."
  exit
fi

echo "Updating rudo..."
git pull

echo "Building rudo..."
cargo build --release $@

echo "Installing rudo binary to /usr/local/bin/..."
cp target/release/rudo /usr/local/bin/rudo
chown -R root:wheel /usr/local/bin/rudo
chmod 4511 /usr/local/bin/rudo

echo "Done updating rudo!"
