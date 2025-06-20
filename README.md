# Guide to Reusing Z-Wave Devices from a Futurehome Hub (gen 1) via SER2NET and Z-Wave JS UI

Futurehome has recently introduced a subscription model. According to their website, local interfaces such as FIMP UI and MQTT will gradually be disabled without an active subscription. As a result, many users risk losing access to their Z-Wave devices and local control.

https://support.futurehome.no/hc/no/articles/28158944965277-FAQ-Abonnement?utm_source=brevo&utm_campaign=Oppdatering%20med%20FAQ&utm_medium=email&utm_id=22

This guide is focused on one thing: reusing the Z-Wave network that are on the Futurehome hub (v1/CUBE-1V0) in Z-Wave JS UI so it can be connected to for example Home Assistant. The goal is to avoid unpairing, and re-pairing the Z-Wave devices. Zigbee, WiFi, or other types of Futurehome-specific integrations are not covered by this guide. Some knowledge of Linux is requred.

Use at your own risk. This guide/script is provided "as is", without any warranty. I am not responsible for any damage, data loss, or issues that may result from using this. Please make sure you understand the steps and adapt them to your specific setup before proceeding.

## Equipment Used

- A Linux machine  
- A Windows machine  
- A micro-USB cable  
- A Raspberry Pi running Z-Wave JS UI
- A Futurehome hub v1

I followed this guide as a base:  
https://community.home-assistant.io/t/how-to-gain-root-to-futurehome-hub-activate-z-wave-js-ui-with-futurehome-app-as-a-fallback/839340  
However, the process below includes more details based on my experience.

---

## 1. Create a SSH Key (Run on the linux machine)

This step generates two files: a private and a public SSH key. The public key must later be added to the `authorized_keys` file on the hub so we can access the hub with root access.

Run the command
```bash
ssh-keygen -t rsa -b 2048 -f ~/.ssh/id_rsa_futurehome
```
This command will generate two SSH key files:

- `~/.ssh/id_rsa_futurehome` (private key)
- `~/.ssh/id_rsa_futurehome.pub` (public key)

You will later copy the public key to the `authorized_keys` file on the hub.

---

## 2. Install Required Tools (Run on the linux machine)

You’ll need to install some dependencies to access the file system on the Futurehome Hub

```bash
sudo apt update
sudo apt install usbutils git libusb-1.0-0-dev
git clone --depth=1 https://github.com/raspberrypi/usbboot
cd usbboot
make
sudo ./rpiboot
```

---

## 3. Access the Hub’s Filesystem  (Run on the linux machine)

Disassemble the hub to expose the micro-USB port. Connect it to your Linux machine and AFTER the usb is connected you can power on the hub with its power adapter. Use lsblk to identify the correct path for the hub storage (for me it was /dev/sda2)

```bash
sudo lsblk
sudo mkdir /mnt/rpi
sudo mount /dev/sda2 /mnt/rpi
```

---

## 4. Backup the Hub  (Run on the linux machine)

Before modifying anything, create a full disk image backup of the hub. Make sure you have the correct device path before executing the command (use lsblk).

Alternatively you can make the backup after you have root access via SSH. Creating a backup is advised, as future updates from Futurehome may revoke root access to the hub, making it impossible to install or run ser2net or similar tools locally. 

```bash
sudo dd if=/dev/sda of=~/futurehome_backup_$(date +%Y%m%d_%H%M%S).img bs=4M status=progress
```
---

## 5. Enable SSH with Root Access  (Run on the linux machine)

Create and run a script that activates the SSH service and injects your public key (ssh key) into the hub's root account. The script also opens port 22 via `iptables` rules.

### Create the script

```bash
nano futurehomerootscript.sh
```

### Paste the following contents into the file:

```bash
#!/bin/bash

PUBKEY_FILE="$HOME/.ssh/id_rsa_futurehome.pub"
MOUNTPOINT="/mnt/rpi"
KEY_DIR="$MOUNTPOINT/root/.ssh"
AUTHORIZED_KEYS="$KEY_DIR/authorized_keys"

# Read the SSH key (assumes it exists)
SSH_KEY=$(cat "$PUBKEY_FILE")

# Enable SSH
sudo ln -sf /lib/systemd/system/ssh.service "$MOUNTPOINT/etc/systemd/system/multi-user.target.wants/ssh.service"

# Open port 22 using iptables via rc.local
sudo sed -i '/^[[:space:]]*exit 0/i iptables -I INPUT -p tcp --dport 22 -j ACCEPT' "$MOUNTPOINT/etc/rc.local"

# Create .ssh directory and add the key
sudo mkdir -p "$KEY_DIR"
echo "$SSH_KEY" | sudo tee "$AUTHORIZED_KEYS" > /dev/null
sudo chmod 700 "$KEY_DIR"
sudo chmod 600 "$AUTHORIZED_KEYS"
sudo chown -R 0:0 "$KEY_DIR"

# Unmount
sudo umount "$MOUNTPOINT"
```

### Make it executable and run it

```bash
chmod +x futurehomerootscript.sh
sudo ./futurehomerootscript.sh
```
---

## 6. Start the Hub and Connect via SSH  (Run on the linux machine)

Disconnect the hub from the linux machine and also the hub's power cord. Then put in the power cord again to power on the futurehome hub.   

Once the hub is restarted, SSH into the hub using your private key and the correct SSH options for RSA support (The ssh server on the hub is outdated).

```bash
ssh -i ~/.ssh/id_rsa_futurehome -o PubkeyAcceptedAlgorithms=+ssh-rsa -o HostKeyAlgorithms=+ssh-rsa root@IPADRESSTOHUB
```

---

## 7. Install and Configure ser2net and Fallback Scripts (Run it on the hub via SSH)

Please note that Dan333 on the Home Assistant forums did all the work, I just formated it to a bash script

You’ll set up `ser2net`, a fallback loop to manage serial port exposure, a web-based control server, and a systemd service to manage it at boot. This part also exposes Z/IP ports used by Silicon Labs tools.

When you are connected to the hub via SSH create the script with nano:

```bash
nano install_ser2net.sh
```

Then paste the following script:

```bash
#!/bin/bash

# CONFIG
mkdir -p /etc/ser2net-server
tee /etc/ser2net-server/config.sh <<EOF
AUTOSTART=yes
FALLBACK=yes
PORT=8091
HOST=
EOF

# INSTALL ser2net
wget -O /tmp/ser2net_2.9.1-1_armhf.deb \
  http://legacy.raspbian.org/raspbian/pool/main/s/ser2net/ser2net_2.9.1-1_armhf.deb
dpkg -i /tmp/ser2net_2.9.1-1_armhf.deb
echo "3333:raw:0:/dev/SER2NET:115200 8DATABITS NONE 1STOPBIT" >> /etc/ser2net.conf
service ser2net restart
sed -i '/^[[:space:]]*exit 0/i iptables -I INPUT -p tcp --dport 3333 -j ACCEPT' /etc/rc.local

# INSTALL ser2net-fallback script
cat <<'EOF' >/usr/local/bin/ser2net-fallback
#!/bin/bash
while true; do
  source /etc/ser2net-server/config.sh
  if [ -z "$HOST" ] || [ -z "$PORT" ]; then
    sleep 60
    continue
  fi
  if [ "$FALLBACK" != "yes" ]; then
    break
  fi
  HOST_UP=$(curl -s --head "http://$HOST:$PORT" > /dev/null && echo "true" || echo "false")
  SER2NET=$(ls -l /dev/SER2NET &>/dev/null && echo 'true' || echo 'false')
  FUTUREHOME=$(ls -l /dev/futurehome/Z-Wave &>/dev/null && echo 'true' || echo 'false')
  if [ "$HOST_UP" = "true" ] && [ "$SER2NET" = "false" ]; then
    /usr/local/bin/ser2net-control start
  elif [ "$HOST_UP" = "false" ] && [ "$FUTUREHOME" = "false" ]; then
    /usr/local/bin/ser2net-control pause
  fi
  sleep 60
done
EOF
chmod +x /usr/local/bin/ser2net-fallback

# INSTALL ser2net-control script
cat <<'EOF' >/usr/local/bin/ser2net-control
#!/bin/bash
source /etc/ser2net-server/config.sh
if [ "$FALLBACK" = "yes" ] && [ "$1" = "start" ]; then
  if ! pgrep -f "ser2net-fallback" >/dev/null; then
    /usr/local/bin/ser2net-fallback &
  fi
fi
case "$1" in
  boot)
    if [ "$AUTOSTART" = "yes" ]; then
      /usr/local/bin/ser2net-control start
    else
      /usr/local/bin/ser2net-control stop
    fi
    ;;
  status)
    echo "FUTUREHOME GATEWAY"
    echo "==== STATUS ===="
    if [ -n "$HOST" ] && [ -n "$PORT" ]; then
      if pgrep -f "ser2net-fallback" >/dev/null; then
        echo "FALLBACK: running"
      else
        echo "FALLBACK: stopped"
      fi
      curl -s --head "http://$HOST:$PORT" >/dev/null && \
        echo "FALLBACK TEST: success" || echo "FALLBACK TEST: host unreachable"
    else
      echo "FALLBACK: missing HOST/PORT"
    fi
    echo "SER2NET: $(ls -l /dev/SER2NET &>/dev/null && echo 'active' || echo 'deactivated')"
    echo "FUTUREHOME: $(ls -l /dev/futurehome/Z-Wave &>/dev/null && echo 'active' || echo 'deactivated')"
    echo "==== CONFIG ===="
    cat /etc/ser2net-server/config.sh
    ;;
  start)
    rm -f /dev/futurehome/Z-Wave &>/dev/null || true
    fuser -k /dev/ttyS0 &>/dev/null || true
    ln -s /dev/ttyS0 /dev/SER2NET &>/dev/null || true
    systemctl restart ser2net &>/dev/null || true
    echo -e "Active: SER2NET\n"
    ;;
  stop)
    killall "ser2net-fallback" &>/dev/null || true
    /usr/local/bin/ser2net-control pause
    ;;
  pause)
    rm -f /dev/SER2NET &>/dev/null || true
    ln -s /dev/ttyS0 /dev/futurehome/Z-Wave &>/dev/null || true
    killall zipgateway &>/dev/null || true
    echo -e "Active: Futurehome\n"
    ;;
  *)
    echo "Usage: $0 {boot|start|stop|status}"
    exit 1
    ;;
esac
EOF
chmod +x /usr/local/bin/ser2net-control

# INSTALL Web control HTTP server
cat <<'EOF' >/usr/local/bin/ser2net-web.py
#!/usr/bin/env python3
import http.server
import socketserver
import subprocess
import shlex
from urllib.parse import urlparse, parse_qs

PORT = 8888
subprocess.check_call(["/usr/local/bin/ser2net-control", "boot"])

class MyHandler(http.server.SimpleHTTPRequestHandler):
    def do_GET(self):
        url_data = urlparse(self.path.lower())
        command = url_data.path.lstrip('/')
        fields=parse_qs(url_data.query)
        if fields:
          config_file = "/etc/ser2net-server/config.sh"
          with open(config_file, "r") as file:
            lines = file.readlines()
          with open(config_file, "w") as file:
            for line in lines:
              key, sep, _ = line.partition("=")
              if key.strip().lower() in ['host', 'port', 'fallback', 'autostart']:
                  value = fields.get(key.lower(), [None])[0]
              if value is not None:
                  value = 'yes' if value in ['yes', 'true', '1'] else ('no' if value in ['no', 'false', '0'] else value)
                  file.write("{key}={value}\n".format(key=key, value=shlex.quote(value)))
                  continue
              file.write(line)
        if command in ['start', 'stop', 'status']:
            response = subprocess.check_output(["/usr/local/bin/ser2net-control", command], universal_newlines=True)
            self.send_response(200)
            self.end_headers()
            self.wfile.write(response.encode('utf-8'))
        else:
            self.send_error(404, "Not Found")

def main():
    httpd = socketserver.TCPServer(("", PORT), MyHandler)
    print("Serving HTTP on port {}".format(PORT))
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        httpd.server_close()

if __name__ == "__main__":
    main()
EOF
chmod +x /usr/local/bin/ser2net-web.py
sed -i '/^[[:space:]]*exit 0/i iptables -I INPUT -p tcp --dport 8888 -j ACCEPT' /etc/rc.local

# CONFIGURE Web control service (autostart)
cat <<'EOF' >/lib/systemd/system/ser2net_web.service
[Unit]
Description=HTTP server to control ser2net/zwave-js / futurehome functions
After=network.target

[Service]
ExecStart=/usr/bin/python3 /usr/local/bin/ser2net-web.py
Restart=always

[Install]
WantedBy=multi-user.target
EOF

ln -sf /lib/systemd/system/ser2net_web.service /etc/systemd/system/multi-user.target.wants/ser2net_web.service
systemctl daemon-reload
systemctl enable ser2net_web.service
systemctl start ser2net_web.service

# EXTRA - Expose Z/IP ports (for Silicon Labs access)
sed -i '/^[[:space:]]*exit 0/i ip6tables -t nat -A PREROUTING -p udp --dport 42242 -j DNAT --to-destination [fd00:aaaa::03]:4123' /etc/rc.local
sed -i '/^[[:space:]]*exit 0/i ip6tables -I INPUT -p udp --dport 42242 -j ACCEPT' /etc/rc.local
```

### Make it executable and run it

```bash
chmod +x install_ser2net.sh
sudo ./install_ser2net.sh
```

---

## 8. Extract the Zwave keys (Run on the Windows machine) 

First, open a web browser and go to:

```
http://IP_ADDRESS_OF_FUTUREHOME:8888/status
```

Here, ensure that Autostart is set to `yes` and that `ser2net` is active.

The next step is to extract the S0 security key. It may not be required, but it’s a precaution. Attempting to connect without the correct key may corrupt your Z-Wave network.

---

### Install and Configure HW Virtual Serial Port

On your Windows machine, download HW Virtual Serial Port (HW VSP3):

 https://www.hw-group.com/software/hw-vsp3-virtual-serial-port

Steps:

- Open the app and go to the "Virtual Serial Port" tab
- Choose an available COM port (e.g., COM7)
- Enter the IP address of the Futurehome hub
- Set port to `3333`
- Click "Create COM"

This will create a virtual serial connection to the `ser2net` service on the hub.

---

### Install Silicon Labs Simplicity Studio

Download Simplicity Studio:
 An account is required to download, but the tool is free to use.

 https://www.silabs.com/developer-tools/z-wave-controller?tab=downloads

Inside the app (this app is a pain to navigate):

- Click **Install**
- Select **Install by technology type**
- Select the **Silicon Labs Matter** tab, then select **Advanced**
- Deselect everything, then select only:
  -  Z-Wave PC Controller
  -  Z-Wave Zniffer

After installation, go to **Tools** and launch **Z-Wave PC Controller**.

---

### Extract the Security Keys

Once Z-Wave PC Controller launches:

- It should detect COM7 automatically (or the port you selected )
- It will scan the port for a while
- In the top-right corner of the app, locate the shield icon (similar to the Windows Defender logo)

Click the shield icon. This will display all security keys.

Copy and save all these keys. You will need them later when setting up Z-Wave JS.

How the keys appear is shown on page 77 of this manual:  
https://www.silabs.com/documents/public/user-guides/INS13114.pdf

Once finished:
- Close PC Controller
- Disable the COM port in HW VSP3

---

## 9. Set Up Z-Wave JS UI

Open Z-Wave JS UI in your browser.

In settings under z-wave:

- Set serial port to:
  ```
  tcp://IP_ADDRESS_OF_FUTUREHOME:3333
  ```
- Paste in all the keys you extracted

**Important:** Ensure the keys are correct. If the S0 key is wrong, your Z-Wave network may need to be rebuilt from scratch.

Once everything was configured, all my devices appeared automatically. It took some time for product names to populate, but the next day everything was correct. I then renamed devices and assigned rooms in Z-Wave JS UI, and connected it to Home Assistant — where name and area carried over correctly.

---

# 10. Block internet access to the hub
I blocked both inbound and outbound internet traffic for the Futurehome hub on my router to prevent it from receiving updates from Futurehome.
