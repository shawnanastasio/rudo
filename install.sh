#!/bin/bash

if [ "$EUID" -ne 0 ]; then 
  echo "Please re-run this script as root."
  exit
fi

echo "Building rudo..."
cargo build --release $@

echo "Generating configuration file..."
target/release/rudo --genconfig > /etc/rudo.json
chown -R root:wheel /etc/rudo.json
chmod 0440 /etc/rudo.json

echo "Installing rudo binary to /usr/local/bin/..."
cp target/release/rudo /usr/local/bin/rudo
chown -R root:wheel /usr/local/bin/rudo
chmod 4511 /usr/local/bin/rudo

echo "Generating PAM configuration..."
unamestr=$(uname)
if [[ "$unamestr" == "Darwin" ]]; then
cat << EOF > /etc/pam.d/rudo
auth       required       pam_opendirectory.so
account    required       pam_permit.so
password   required       pam_deny.so
session    required       pam_permit.so
EOF
else
cat << EOF > /etc/pam.d/rudo
auth       include      system-auth
account    include      system-auth
password   include      system-auth
session    optional     pam_keyinit.so revoke
session    required     pam_limits.so
session    include      system-auth
EOF
fi

chmod 0644 /etc/pam.d/rudo

echo "Done installing rudo!"
echo "Please edit /etc/rudo.json to add your user."
