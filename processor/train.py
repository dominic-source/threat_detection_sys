"""Train an IsolationForest on a CSV of `payload_size` values and save model.pkl

Usage:
  python train.py --input ../data/sample_dataset.csv --output model.pkl
"""
import argparse
import numpy as np
import joblib
from sklearn.ensemble import IsolationForest


def load_csv(path):
    data = np.loadtxt(path, delimiter=',', skiprows=1)
    return data.reshape(-1, 1)


def main():
    p = argparse.ArgumentParser()
    p.add_argument('--input', '-i', default='../data/sample_dataset.csv')
    p.add_argument('--output', '-o', default='model.pkl')
    args = p.parse_args()

    X = load_csv(args.input)
    model = IsolationForest(n_estimators=64, contamination=0.02, random_state=42)
    model.fit(X)
    joblib.dump(model, args.output)
    print(f"Saved model to {args.output}")


if __name__ == '__main__':
    main()
