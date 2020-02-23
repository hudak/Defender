import argparse
from pathlib import Path
import json
import gzip
from typing import NamedTuple, Dict, List

import pandas as pd
from tqdm import tqdm

parser = argparse.ArgumentParser()
parser.add_argument('log_dir', type=Path, nargs='*', default=[Path('AWSLogs')],
                    help='Location of AWS CloudTrail logs')
parser.add_argument('--describe-events', action='store_true', help='Count types of observed events.')


class Record(NamedTuple):
    eventVersion: int
    idType: str
    principalId: str
    arn: str

    eventName: str
    eventTime: pd.Timestamp

    awsRegion: str
    sourceIPAddress: str
    userAgent: str

    eventID: str
    eventType: str

    @classmethod
    def read_obj(cls, obj):
        """
        Factory method to read fields from parsed JSON object.
        :param obj: mapping from json reader
        :return: Record named tuple
        """
        record_fields = {
            'eventVersion': float,
            'eventName': str,
            'eventTime': pd.Timestamp,
            'awsRegion': str,
            'sourceIPAddress': str,
            'userAgent': str,
            'eventID': str,
            'eventType': str,
        }

        values = {k: t(obj[k]) for k, t in record_fields.items()}

        uid: Dict = obj['userIdentity']
        identity_fields = {
            'type': 'idType',
            'principalId': 'principalId',
            'arn': 'arn',
        }
        values.update({f: uid.get(k) for k, f in identity_fields.items()})

        return cls(**values)


def main():
    args = parser.parse_args()
    print(args)
    # Find all log files
    glob_patterns = ['*.json', '*.json.gz']
    log_files = set(f for d in args.log_dir if d.is_dir() for g in glob_patterns for f in d.rglob(g))

    print(f"Found {len(log_files)} files")
    print('\n'.join('  ' + f.name for f in log_files))

    # Open files, collect all found records
    records = load_files(log_files)
    print(f'Found {len(records)} records')

    if args.describe_events:
        print(records.groupby(['eventType', 'eventName']).size())


def load_files(log_files: List[Path]) -> pd.DataFrame:
    records = []
    for f in tqdm(log_files, desc='Reading log files', unit='file'):
        obj = load_file(f)

        for rec in obj['Records']:
            records.append(Record.read_obj(rec))

    return pd.DataFrame.from_records(records, columns=Record._fields)


def load_file(f: Path):
    # Decompress if needed
    if f.match("*.gz"):
        f = gzip.open(f)

    return json.load(f)


if __name__ == '__main__':
    main()
