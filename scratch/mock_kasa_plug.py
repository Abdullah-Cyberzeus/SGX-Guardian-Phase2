import socket
import json
import threading

def encrypt_udp(string):
    key = 0xAB
    result = bytearray()
    for i in string.encode():
        a = key ^ i
        key = a
        result.append(a)
    return result

def encrypt_tcp(string):
    key = 0xAB
    result = bytearray((len(string)).to_bytes(4, 'big'))
    for i in string.encode():
        a = key ^ i
        key = a
        result.append(a)
    return result

def decrypt(data):
    key = 0xAB
    result = []
    for i in data:
        a = key ^ i
        key = i
        result.append(a)
    return bytes(result).decode('utf-8', errors='ignore')

full_sysinfo = {
    "system": {
        "get_sysinfo": {
            "err_code": 0,
            "sw_ver": "1.2.6 Build 200727 Rel.121548",
            "hw_ver": "2.0",
            "type": "IOT.SMARTPLUGSWITCH",
            "model": "HS110(US)",
            "mac": "50:C7:BF:00:11:22",
            "deviceId": "8006C7BF00112233445566778899AA",
            "hwId": "A123B456C789D012E345F67890ABCDEF",
            "fwId": "00000000000000000000000000000000",
            "oemId": "FFF111222333444555666777888999AA",
            "alias": "Mock Kasa Smart Plug",
            "dev_name": "Smart Wi-Fi Plug",
            "relay_state": 1,
            "on_time": 3600,
            "active_mode": "none",
            "feature": "TIM:ENE",
            "updating": 0,
            "rssi": -55,
            "led_off": 0,
            "latitude_i": 0,
            "longitude_i": 0
        }
    },
    "emeter": {
        "get_realtime": {
            "current_ma": 35,
            "voltage_mv": 120100,
            "power_mw": 4200,
            "total_wh": 150,
            "err_code": 0
        },
        "get_daystat": {
            "day_list": [],
            "err_code": 0
        },
        "get_monthstat": {
            "month_list": [],
            "err_code": 0
        }
    },
    "time": {
        "get_time": {
            "year": 2026,
            "month": 7,
            "mday": 29,
            "hour": 12,
            "min": 0,
            "sec": 0,
            "err_code": 0
        },
        "get_timezone": {
            "index": 1,
            "err_code": 0
        }
    },
    "schedule": {
        "get_next_action": {
            "err_code": 0
        }
    },
    "count_down": {
        "get_rules": {
            "rule_list": [],
            "err_code": 0
        }
    },
    "anti_theft": {
        "get_rules": {
            "rule_list": [],
            "err_code": 0
        }
    }
}

def handle_request(req_json):
    resp = {}
    if not isinstance(req_json, dict):
        return full_sysinfo

    for mod_key, mod_dict in req_json.items():
        resp[mod_key] = {}
        if isinstance(mod_dict, dict):
            for cmd_key, cmd_val in mod_dict.items():
                if cmd_key == "set_relay_state" and isinstance(cmd_val, dict):
                    st = cmd_val.get("state", 0)
                    full_sysinfo["system"]["get_sysinfo"]["relay_state"] = st
                    print(f"🔌 [MOCK KASA] Relay state changed to: {st}")
                    resp[mod_key][cmd_key] = {"err_code": 0}
                elif cmd_key == "set_led_off" and isinstance(cmd_val, dict):
                    off_st = cmd_val.get("off", 0)
                    full_sysinfo["system"]["get_sysinfo"]["led_off"] = off_st
                    print(f"💡 [MOCK KASA] LED Off state changed to: {off_st}")
                    resp[mod_key][cmd_key] = {"err_code": 0}
                elif mod_key in full_sysinfo and cmd_key in full_sysinfo[mod_key]:
                    resp[mod_key][cmd_key] = full_sysinfo[mod_key][cmd_key]
                else:
                    resp[mod_key][cmd_key] = {"err_code": 0}
        else:
            resp[mod_key] = {"err_code": 0}

    return resp

def udp_server():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(('0.0.0.0', 9999))
    print("🔌 Virtual Kasa UDP Server listening on 0.0.0.0:9999")
    while True:
        try:
            data, addr = sock.recvfrom(1024)
            sock.sendto(encrypt_udp(json.dumps(full_sysinfo)), addr)
        except Exception as e:
            print(f"UDP Error: {e}")

def tcp_server():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(('0.0.0.0', 9999))
    server.listen(5)
    print("🔌 Virtual Kasa TCP Server listening on 0.0.0.0:9999")
    while True:
        try:
            conn, addr = server.accept()
            raw = conn.recv(2048)
            if raw and len(raw) > 4:
                req_text = decrypt(raw[4:])
                print(f"📩 TCP Request: {req_text}")
                try:
                    req_json = json.loads(req_text)
                    resp = handle_request(req_json)
                    conn.sendall(encrypt_tcp(json.dumps(resp)))
                except Exception as e:
                    print(f"Error handling JSON request: {e}")
                    conn.sendall(encrypt_tcp(json.dumps(full_sysinfo)))
            else:
                conn.sendall(encrypt_tcp(json.dumps(full_sysinfo)))
            conn.close()
        except Exception as e:
            print(f"TCP Error: {e}")

if __name__ == "__main__":
    t_udp = threading.Thread(target=udp_server, daemon=True)
    t_tcp = threading.Thread(target=tcp_server, daemon=True)
    t_udp.start()
    t_tcp.start()
    print("🚀 Virtual TP-Link Kasa Smart Plug Simulator started (UDP+TCP port 9999)...")
    t_udp.join()
    t_tcp.join()
