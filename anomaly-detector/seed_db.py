"""Seed explicitly approved normal baseline data, without fabricating results."""
import argparse
import datetime as dt
import json
from database import connect, initialize

def seed(path):
    initialize(path)
    now=dt.datetime.now(dt.timezone.utc)
    with connect(path) as conn:
        for i in range(200):
            conn.execute('''INSERT OR IGNORE INTO api_traffic(request_id,method,path,request_body,response_body,status_code,timestamp,
                graph_path_template,graph_known,graph_context_status,graph_deprecated,graph_security,spec_title,spec_version,training_eligible)
                VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,1)''',
                (f'baseline-{i}','GET',f'/v2/items/{i}','',json.dumps({'data':'x'*(20+i%8)}),200,
                 (now-dt.timedelta(minutes=200-i)).isoformat(),'/v2/items/{id}',1,'resolved',0,'[]','resource','1'))

if __name__=='__main__':
    parser=argparse.ArgumentParser();parser.add_argument('--db',default='../traffic.db');args=parser.parse_args();seed(args.db)
