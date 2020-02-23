import json
import sys


def main():
    obj = json.load(sys.stdin)
    policy = json.loads(obj['policyText'])
    print(json.dumps(policy, indent=2))


if __name__ == '__main__':
    main()
