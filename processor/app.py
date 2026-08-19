import os
import time
from collections import deque

import numpy as np
from redis import Redis
from sklearn.ensemble import IsolationForest
import joblib

REDIS_ADDR = os.getenv("REDIS_ADDR", "localhost:6379")
MODEL_PATH = os.getenv("MODEL_PATH", "model.pkl")
redis = Redis.from_url(f"redis://{REDIS_ADDR}")

STREAM = "stream:telemetry"
GROUP = "processor-group"
CONSUMER = "processor-1"

WINDOW = 256
THRESHOLD = -0.1


def ensure_group():
    try:
        redis.xgroup_create(STREAM, GROUP, id="0", mkstream=True)
    except Exception:
        pass


def parse_entry(entry):
    _, vals = entry
    data = {}
    for k, v in vals.items():
        key = k.decode() if isinstance(k, bytes) else k
        if isinstance(v, bytes):
            try:
                sval = v.decode()
                if sval.isdigit():
                    data[key] = int(sval)
                else:
                    data[key] = sval
            except Exception:
                data[key] = v
        else:
            data[key] = v
    return data


def load_pretrained(path):
    if os.path.exists(path):
        try:
            model = joblib.load(path)
            print(f"Loaded pretrained model from {path}")
            return model
        except Exception as e:
            print(f"Failed to load pretrained model: {e}")
    return None


def main():
    ensure_group()
    buffer = deque(maxlen=WINDOW)
    model = load_pretrained(MODEL_PATH)

    while True:
        # BLOCK for new messages
        resp = redis.xreadgroup(GROUP, CONSUMER, {STREAM: ">"}, block=5000, count=10)
        if not resp:
            continue
        for stream_name, messages in resp:
            for msg_id, msg in messages:
                entry = parse_entry((msg_id, msg))
                # Build simple feature vector
                sz = int(entry.get("payload_size", 0))
                feat = np.array([sz], dtype=float)
                buffer.append(feat)

                if model is None and len(buffer) >= 32:
                    X = np.vstack(buffer)
                    model = IsolationForest(n_estimators=64, contamination=0.01, random_state=42)
                    model.fit(X)
                    # Optionally persist model for future runs
                    try:
                        joblib.dump(model, MODEL_PATH)
                        print(f"Saved trained model to {MODEL_PATH}")
                    except Exception:
                        pass

                if model is not None:
                    score = float(model.decision_function(feat.reshape(1, -1))[0])
                    if score < THRESHOLD:
                        user = entry.get("user_id_hash")
                        if user:
                            key = f"blocklist:{user}"
                            # set TTL 300s
                            redis.set(key, score, ex=300)
                            print(f"Blocked user {user[:8]} score={score}")

                # Acknowledge
                try:
                    redis.xack(STREAM, GROUP, msg_id)
                except Exception:
                    pass


if __name__ == "__main__":
    print(f"processor connecting to {REDIS_ADDR}")
    main()
