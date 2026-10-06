"""Three resettable HTTP testbeds. Runtime behavior and truth are independent of Sentry."""
import argparse
import json
import random
import threading
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

APPS = ('resource', 'versioned', 'gateway')
SCHEMA = {'type':'object','required':['data'],'properties':{'data':{'type':'string'}}}

def specification(app, port=0):
    paths = {}
    for route, deprecated, public, schema in [
        ('/v2/items/{id}',False,True,True),('/v2/profile',False,True,True),
        ('/v2/large',False,True,True),('/v2/new',False,True,True),
        ('/v1/items/{id}',True,True,True),('/v1/protected',True,False,True),
        ('/v1/public',True,True,False),('/v1/retired',True,True,True),
        ('/v1/redirect',True,True,False),('/v1/waf',True,True,True),
        ('/v1/mismatch',True,True,True),('/v2/error',False,True,True),
    ]:
        response = {'description':'Successful response'}
        if schema:
            response['content']={'application/json':{'schema':SCHEMA}}
        operation={'deprecated':deprecated,'security':[] if public else [{'bearer':[]}], 'responses':{'200':response}}
        if '{id}' in route:
            operation['parameters']=[{'name':'id','in':'path','required':True,'schema':{'type':'integer'},'example':1}]
        paths[route]={'get':operation}
    return {'openapi':'3.0.3','info':{'title':app,'version':'1'},
            'servers':[{'url':f'http://127.0.0.1:{port}'}],
            'components':{'securitySchemes':{'bearer':{'type':'http','scheme':'bearer'}}},'paths':paths}

# Truth describes actual inventory/lifecycle discrepancies, not exploitability.
def truth(app):
    positive={('GET','/v1/items/{id}'),('GET','/v1/protected'),('GET','/v1/public'),
              ('GET','/v1/profile'),('GET','/private/export'),('GET','/debug')}
    return {'app':app,'positive_endpoints':[list(key) for key in sorted(positive)],
            'negative_endpoints':[['GET',p] for p in ['/v2/items/{id}','/v2/profile','/v2/large','/v2/new','/v1/retired','/v1/redirect','/v1/waf','/v1/mismatch','/v2/error','/nonsense']],
            'authentication_exposures':[['GET','/v1/protected']],
            'labels_definition':'Actionable inventory/lifecycle discrepancy; authentication exposure measured separately'}

class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def do_GET(self): self.handle_request()
    def do_HEAD(self): self.handle_request()
    def do_OPTIONS(self): self.handle_request()
    def do_POST(self): self.handle_request()
    def do_PUT(self): self.handle_request()
    def do_PATCH(self): self.handle_request()
    def do_DELETE(self): self.handle_request()

    def handle_request(self):
        from urllib.parse import urlsplit, parse_qs
        url=urlsplit(self.path); query=parse_qs(url.query);path=url.path
        self.server.count += 1
        code=200; body={'data':'ok'};headers={'Content-Type':'application/json'}
        if path=='/__reset' and self.command=='POST':
            self.server.count=0;body={'reset':True}
        elif path=='/__health':body={'app':self.server.app}
        elif path=='/openapi.json':body=specification(self.server.app,self.server.server_port)
        elif self.command!='GET':code=405;body={'error':'method not supported'}
        elif path.startswith('/v2/items/') or path.startswith('/v1/items/'):
            body={'data':'item-'+path.rsplit('/',1)[-1]}
        elif path in ['/v2/profile','/v1/profile','/v2/new','/v1/protected','/v1/public']:
            body={'data':'profile-'+self.server.app}
        elif path=='/v2/large':body={'data':'x'*4000}
        elif path in ['/private/export','/debug']:body={'data':'internal-'+self.server.app}
        elif path=='/v1/retired':code=410;body={'error':'retired'}
        elif path=='/v1/redirect':code=302;headers['Location']='/login';body={'login':True}
        elif path=='/v1/waf':code=403;body={'error':'blocked'}
        elif path=='/v1/mismatch':body={'error':'retired'}
        elif path=='/v2/error':code=400;body={'error':'bad request'}
        elif self.server.app=='gateway':body={'error':'unknown route','request_id':str(uuid.uuid4())}
        else:code=404;body={'error':'unknown route','request_id':str(uuid.uuid4())}
        # Behavioral anomalies alter existing normal operations, independently of inventory truth.
        if query.get('payload')==['large'] and path=='/v2/items/1':body={'data':'x'*100000};code=500
        if query.get('size') and path=='/v2/profile':body={'data':'x'*int(query['size'][0])}
        raw=json.dumps(body,sort_keys=True).encode();self.send_response(code)
        for key,value in headers.items():self.send_header(key,value)
        self.send_header('Content-Length',str(len(raw)));self.end_headers()
        if self.command!='HEAD':self.wfile.write(raw)


def start(app, port=0):
    server=ThreadingHTTPServer(('127.0.0.1',port),Handler);server.app=app;server.count=0
    worker=threading.Thread(target=server.serve_forever,daemon=True);worker.start()
    return server

if __name__=='__main__':
    parser=argparse.ArgumentParser();parser.add_argument('--app',choices=APPS,default='resource');parser.add_argument('--port',type=int,default=9001);parser.add_argument('--output',default='research/generated');parser.add_argument('--host',default='127.0.0.1');args=parser.parse_args()
    directory=Path(args.output);directory.mkdir(parents=True,exist_ok=True)
    (directory/f'{args.app}.json').write_text(json.dumps(specification(args.app,args.port),indent=2))
    (directory/f'{args.app}-truth.json').write_text(json.dumps(truth(args.app),indent=2))
    server=ThreadingHTTPServer((args.host,args.port),Handler);server.app=args.app;server.count=0
    print(f'{args.app} testbed on {args.host}:{args.port}',flush=True)
    server.serve_forever()
