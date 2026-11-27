#!/usr/bin/env python3
import sys
import time
import os
import signal
import requests
import urllib3

# Disable SSL verification warnings (mirrors curl -k)
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Global runtime states matching the bash logic
RUNNING = 0
IP = ""
PASSWORD = ""
SENDER_ID = ""
PORT = ""
FILENAME = ""
DESTPATH = ""
COUNT = ""
CAPLEN = ""
VIDEO = ""

# Reusable session to automatically persist cookies between HMI login and download
session = requests.Session()

def parse_arguments():
    """Parses and validates long command-line options."""
    import argparse
    parser = argparse.ArgumentParser(
        description="VIP Packet Capture Tool",
        usage="python vip_packet_capture_sender_id.py --ip <IP> --password <admin password> --sender-id <sender_id> --port <A|B> --filename <capture filename> --dest <destination path> --count <count> --caplen <caplen> --video <true|false>"
    )
    parser.add_argument("--ip", required=True, help="VIP IP address")
    parser.add_argument("--password", required=True, help="Admin password")
    parser.add_argument("--sender-id", required=True, help="Sender ID")
    parser.add_argument("--filename", required=True, help="Capture filename")
    parser.add_argument("--dest", default=".", help="Local path where the file should be saved (default: current directory)")
    parser.add_argument("--port", default="A", help="Port (e.g., A or B), default A")
    parser.add_argument("--count", default="0", help="Packet count threshold (default max)")
    parser.add_argument("--caplen", default="1500", help="Capture packet length (default 1500)")
    parser.add_argument("--video", default="false", choices=["true", "false"], help="Capture complete video frames, default false")
    
    try:
        return parser.parse_args()
    except SystemExit:
        sys.exit(1)

def cleanup_handler(signum, frame):
    """Handles Ctrl+C traps, stops active captures, and attempts downloading."""
    print("\nScript interrupted by user. Stopping capture and downloading file if it exists...")
    if RUNNING == 1:
        vip_rest_capture_stop()
        time.sleep(2)
        vip_hmi_capture_download()
    sys.exit(1)

def vip_rest_login():
    """Logs into the VIP REST engine."""
    print(f"Logging in to VIP @ {IP}")
    url = f"https://{IP}:8445/vip"
    headers = {"Content-Type": "application/json"}
    payload = {
        "op": "login",
        "user": "admin",
        "args": {
            "password": PASSWORD
        }
    }
    try:
        response = session.post(url, json=payload, headers=headers, verify=False, timeout=15)
        if "Success" not in response.text:
            print(f"Login Failed, status code = {response.status_code}")
            sys.exit(-1)
    except requests.RequestException as e:
        print(f"Login connection failure: {e}")
        sys.exit(-1)

def vip_rest_logout():
    """Logs out from the VIP REST interface."""
    url = f"https://{IP}:8445/vip"
    headers = {"Content-Type": "application/json"}
    payload = {
        "op": "logout",
        "user": "admin"
    }
    try:
        response = session.post(url, json=payload, headers=headers, verify=False, timeout=15)
        msg = response.text
        if "Success" not in msg:
            try:
                parts = msg.split(":")
                if len(parts) > 1:
                    clean_msg = parts[1].split(",")[0].replace('"', '').strip()
                    print(clean_msg)
                else:
                    print(msg.replace('"', '').strip())
            except Exception:
                print(msg)
        else:
            print(f"Logged out from VIP @ {IP}")
    except requests.RequestException as e:
        print(f"Logout connection error: {e}")

def vip_rest_capture_start():
    """Instructs the backend to begin packet collection."""
    global RUNNING
    url = f"https://{IP}:8445/vip"
    headers = {"Content-Type": "application/json"}
    payload = {
        "op": "packetcapture",
        "user": "admin",
        "args": {
            "cmd": "captureStartSenderId",
            "filename": FILENAME,
            "id": SENDER_ID,
            "port": PORT,
            "count": COUNT,
            "caplen": CAPLEN,
            "capVideoFrames": VIDEO
        }
    }
    try:
        response = session.post(url, json=payload, headers=headers, verify=False, timeout=15)
        msg = response.text
        if "Fail" in msg:
            try:
                if "Failure:" in msg:
                    msg = msg.split("Failure:")[1].split("stackMsg")[0].split('"')[0].strip()
            except Exception:
                pass
            print(f"Capture Start failed: {msg}")
            sys.exit(-1)
        else:
            print("Capture Started.")
            RUNNING = 1
    except requests.RequestException as e:
        print(f"Capture initialization failed: {e}")
        sys.exit(-1)

def vip_rest_capture_poll():
    """Polls the capture status continuously until execution marks Done."""
    print("Capturing packets....")
    url = f"https://{IP}:8445/vip"
    headers = {"Content-Type": "application/json"}
    payload = {
        "op": "packetcapture",
        "user": "admin",
        "args": {
            "cmd": "captureStatusSenderId",
            "id": SENDER_ID,
            "port": PORT
        }
    }
    done = False
    while not done:
        time.sleep(1)
        try:
            response = session.post(url, json=payload, headers=headers, verify=False, timeout=15)
            msg = response.text
            try:
                words = msg.split()
                if VIDEO == "true":
                    packets = words[3].split(",")[0] if len(words) > 3 else "0"
                    frames = words[7].split('"')[0] if len(words) > 7 else "0"
                    print(f"Captured {frames} video frames, {packets} packets", end="\r", flush=True)
                else:
                    packets = words[3].split('"')[0] if len(words) > 3 else "0"
                    print(f"Captured {packets} packets", end="\r", flush=True)
            except Exception:
                pass
            if "Done" in msg:
                done = True
                print("") # Clear carriage return track
        except requests.RequestException:
            pass

def vip_rest_capture_stop():
    """Forces the target device to commit and write packet streams to storage."""
    print("Capture completed, processing packets....please wait")
    url = f"https://{IP}:8445/vip"
    headers = {"Content-Type": "application/json"}
    payload = {
        "op": "packetCapture",
        "user": "admin",
        "args": {
            "cmd": "captureStopSenderId",
            "id": SENDER_ID,
            "port": PORT
        }
    }
    try:
        response = session.post(url, json=payload, headers=headers, verify=False, timeout=30)
        msg = response.text
        if "Fail" in msg:
            print("Capture Failed.")
            sys.exit(-1)
        else:
            print("Capture Finished.")
            try:
                if "Success:" in msg:
                    msg = msg.split("Success:")[1].split("stackMsg")[0].split('"')[0].strip()
            except Exception:
                pass
            print(msg)
    except requests.RequestException as e:
        print(f"Failed stopping capture cleanly: {e}")
        sys.exit(-1)

def vip_hmi_capture_download():
    """Performs form-based portal authentication to fetch the capture file."""
    # Build complete destination save path
    full_destination_path = os.path.join(DESTPATH, FILENAME)
    
    print(f"Downloading capture file {FILENAME} to {full_destination_path}")
    login_url = f"https://{IP}/auth/login"
    download_url = f"https://{IP}/transfer/download/{FILENAME}"
    form_data = {
        "username": "admin",
        "password": PASSWORD
    }
    try:
        # Step 1: Login to portal front-end
        session.post(login_url, data=form_data, verify=False, timeout=15)
        
        # Ensure destination directory structure exists before building file pointer
        if DESTPATH != ".":
            os.makedirs(DESTPATH, exist_ok=True)

        # Step 2: Extract download payload in buffered streams
        with session.get(download_url, verify=False, stream=True, timeout=60) as r:
            r.raise_for_status()
            with open(full_destination_path, 'wb') as f:
                for chunk in r.iter_content(chunk_size=8192):
                    f.write(chunk)
        print(f"File successfully written locally: {full_destination_path}")
    except requests.RequestException as e:
        print(f"HMI download workflow failed: {e}")

def main():
    global IP, PASSWORD, SENDER_ID, PORT, FILENAME, DESTPATH, COUNT, CAPLEN, VIDEO
    
    # Attach interrupt signal hook (Ctrl+C trap emulation)
    signal.signal(signal.SIGINT, cleanup_handler)
    
    # Bind processed input options
    args = parse_arguments()
    IP = args.ip
    PASSWORD = args.password
    SENDER_ID = args.sender_id
    PORT = args.port
    FILENAME = args.filename
    DESTPATH = args.dest
    COUNT = args.count
    CAPLEN = args.caplen
    VIDEO = args.video
    
    # Native routine pipeline implementation
    vip_rest_login()
    vip_rest_capture_start()
    vip_rest_capture_poll()
    time.sleep(2)
    vip_rest_capture_stop()
    time.sleep(2)
    vip_rest_logout()
    vip_hmi_capture_download()

if __name__ == "__main__":
    main()

