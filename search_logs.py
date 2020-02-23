import argparse
from pathlib import Path
import json
import gzip
from typing import NamedTuple, Dict, List
import re
import socket

import pandas as pd
from tqdm import tqdm

parser = argparse.ArgumentParser()
parser.add_argument('log_dir', type=Path, nargs='*', default=[Path('AWSLogs')],
                    help='Location of AWS CloudTrail logs')
parser.add_argument('-r', '--roles', type=argparse.FileType('r'), help='IAM role info as JSON')

actions = parser.add_mutually_exclusive_group()
actions.add_argument('--describe-events', action='store_true', help='Count types of observed events.')
actions.add_argument('--find-intruders', action='store_true', help='Highlight records from non-AWS IPs.')

query = actions.add_mutually_exclusive_group()
query.add_argument('-q', '--query', help='Query records with simple pandas syntax.')
parser.add_argument('-f', '--fields', nargs='+', help='Query output fields')


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

    role: str = None
    role_principal: str = None

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
    # Find all log files
    glob_patterns = ['*.json', '*.json.gz']
    log_files = set(f for d in args.log_dir if d.is_dir() for g in glob_patterns for f in d.rglob(g))

    print(f"Found {len(log_files)} files")
    print('\n'.join('  ' + f.name for f in log_files))

    # Open files, collect all found records
    records = load_files(log_files)
    records.sort_values('eventTime', inplace=True)

    # Extract assumed role from records
    has_arn = pd.notna(records.arn)
    records.loc[has_arn, 'role'] = records[has_arn].apply(role_from_record, axis=1)

    # Augment records with role info
    roles = load_roles(args.roles) if args.roles else None
    if roles is not None:
        records['role_principal'] = records.role.map(roles.principal)

    print(f'Found {len(records)} records')

    if args.describe_events:
        print(records.groupby(['eventType', 'eventName']).size())

    elif args.find_intruders:
        # Mark records from aws internal hosts as safe
        src_ip = records.sourceIPAddress
        aws_host = src_ip.str.endswith('amazonaws.com')
        records['awsHost'] = aws_host

        unknown_hosts = src_ip[~aws_host].unique()
        # Lookup unknown hosts
        for addr in tqdm(unknown_hosts, desc='Scanning unknown hosts', unit='ipAddr'):
            try:
                host = socket.gethostbyaddr(addr)[0]
                records.loc[src_ip == addr, 'awsHost'] = host.endswith('amazonaws.com')
            except OSError:
                pass

        # Report intruders
        intruders = src_ip[~records.awsHost].unique()

        if intruders:
            print(f'Found possible attackers:', intruders)

        for addr in intruders:
            print(f'{addr} Activity:')
            print(records.loc[src_ip == addr, ['eventTime', 'eventName', 'role', 'role_principal']])

    elif args.query:
        df: pd.DataFrame = records.query(args.query)

        if args.fields:
            df = df.loc[:, args.fields]

        print('Query Result:')
        print(df)


def role_from_record(record):
    match = re.search(r':assumed-role/([^/]+)/', record.arn)
    if match:
        return match.group(1)


def load_roles(json_file):
    role_fields = ['name', 'type', 'principal']

    def extract_role(role_obj):
        name = role_obj['RoleName']
        policy_doc = role_obj['AssumeRolePolicyDocument']

        for statement in policy_doc['Statement']:
            for role_type, principal in statement['Principal'].items():
                yield name, role_type, principal

    role_objects = json.load(json_file)['Roles']
    roles = [role for obj in role_objects for role in extract_role(obj)]
    return pd.DataFrame.from_records(roles, index='name', columns=role_fields)


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
