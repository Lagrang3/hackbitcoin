from hackbitcoin.rpc import bitcoin_RPC

# Example use of bitcoin_RPC to search for the first bitcoin transaction
def search():
    def get_block_hash(i):
        return bitcoin_RPC.request('getblockhash',params={'height':i})
    def get_block(h):
        return bitcoin_RPC.request('getblock',params={'blockhash':h,'verbosity':2})
    def search_txs(b):
        def matches(tx):
            has_25 = False
            has_opreturn = False
            # if \
            # tx['txid']=='577aade7b73cf91923730298f283251344d43f8ae802bd2b70348ee7111576ce':
            #     return True
            for o in tx['vout']:
                if o['scriptPubKey']['type']=='nulldata' and o['value']==0.0:
                    has_opreturn = True
                if o['scriptPubKey']['type']=='witness_v0_keyhash' and o['value']==0.00025000:
                    has_25 = True
            return has_25 and has_opreturn

        for tid in b['tx']:
            try:
                raw = bitcoin_RPC.request('getrawtransaction',params={'txid':tid})
                decode = bitcoin_RPC.request('decoderawtransaction',params={'hexstring':raw})
                if matches(decode):
                    print(tid)
                    with open('/tmp/searchlog.txt','a') as f:
                        print(tid,file=f)
            except:
                continue

    def search_txs_2(b):
        def matches(tx):
            has_25 = False
            has_opreturn = False
            for o in tx['vout']:
                if o['scriptPubKey']['type']=='nulldata' and o['value']==0.0:
                    has_opreturn = True
                if o['scriptPubKey']['type']=='witness_v0_keyhash' and o['value']==0.00025000:
                    has_25 = True
            return has_25 and has_opreturn

        for tx in b['tx']:
            if matches(tx):
                tid = tx['txid']
                print(tid)
                with open('/tmp/searchlog.txt','a') as f:
                    print(tid,file=f)

    count = 750000
    #count = 820823
    h = get_block_hash(count)
    while True:
        print('Checking block {}, hash = {}'.format(count,h))
        b = get_block(h)

        search_txs_2(b)

        # the end
        if b['confirmations']==1:
            break

        h = b['nextblockhash']
        count += 1

search()
