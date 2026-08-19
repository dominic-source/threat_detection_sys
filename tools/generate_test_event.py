import requests
import time

for i in range(5):
    r = requests.post("http://localhost:8080/test", json={"user_id": "alice", "n": i})
    print(r.status_code, r.text)
    time.sleep(0.2)
