import requests
import json

class bitcoin_RPC:
    headers = {'content-type':'application/json','cache-control':'no-cache'}

    @classmethod
    def load_conf(cls):
        with open('bitcoinconf.json','r') as fd:
            data = json.load(fd)
            cls.rpc_user = data['rpcuser']
            cls.rpc_pass = data['rpcpassword']
            cls.url = data['rpcconnect']

    @classmethod
    def request(cls,method,params,network='mainnet'):
        cls.load_conf()
        # FIXME: support for testnet
        if network!='mainnet':
            raise ValueError('Network {} is not supported'.format(network))
        data = json.dumps({'method':method,'params':params})
        response = requests.request('POST',
                        url=cls.url,
                        data=data,
                        headers=cls.headers,
                        auth=(cls.rpc_user,cls.rpc_pass))
        d = json.loads(response.text)
        if d['error']:
            raise RuntimeError('Request returned with error {}'.format(d['error']))
        return d['result']

# Example use of bitcoin_RPC to search for the first bitcoin transaction
def search():
    def get_block_hash(i):
        return bitcoin_RPC.request('getblockhash',params={'height':i})
    def get_block(h):
        return bitcoin_RPC.request('getblock',params={'blockhash':h})

    # genesis block
    h = get_block_hash(0)
    count = 0
    while True:
        print('Checking block {}, hash = {}'.format(count,h))
        b = get_block(h)
        if b['nTx']>1:
            print(b)
            return b['tx'][1]
        h = b['nextblockhash']
        count += 1
