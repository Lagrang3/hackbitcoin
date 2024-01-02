class Network_class:
    def __init__(self):
        self.hdwallet_encodings = {}
        self.hdwallet_inverse = {}

        codes = [ \
            # BIP32
            ('pubk', 'P2PKH', 'mainnet', '0488b21e'),
            ('priv', 'P2PKH', 'mainnet', '0488ade4'),
            ('pubk', 'P2PKH', 'testnet', '043587cf'),
            ('priv', 'P2PKH', 'testnet', '04358394'),

            # BIP49
            ('pubk', 'P2SH(P2WPKH)', 'mainnet', '049d7cb2'),
            ('priv', 'P2SH(P2WPKH)', 'mainnet', '049d7878'),
            ('pubk', 'P2SH(P2WPKH)', 'testnet', '044a5262'),
            ('priv', 'P2SH(P2WPKH)', 'testnet', '044a4e28'),

            # BIP84
            ('pubk', 'P2WPKH', 'mainnet', '04b24746'),
            ('priv', 'P2WPKH', 'mainnet', '04b2430c'),
            ('pubk', 'P2WPKH', 'testnet', '045f1cf6'),
            ('priv', 'P2WPKH', 'testnet', '045f18bc'),
            ]

        for priv, scheme, net, hexc in codes:
            self.hdwallet_encodings[(priv, scheme, net)] = bytes.fromhex(hexc)
            self.hdwallet_inverse[bytes.fromhex(hexc)] = (priv, scheme, net)


        self.address_encodings = {}
        self.address_inverse = {}

        codes = [\
            ('P2PKH', 'mainnet', '00'),
            ('P2PKH', 'testnet', '6f'),

            # BIP13
            ('P2SH', 'mainnet', '05'),
            ('P2SH', 'testnet', 'c4'),
            ]

        for scheme, net, hexc in codes:
            self.address_encodings[(scheme, net)] = bytes.fromhex(hexc)
            self.address_inverse[bytes.fromhex(hexc)] = (scheme, net)


        self.wif_encodings = {}
        self.wif_inverse = {}

        codes = [\
            ('mainnet', '80'),
            ('testnet', 'ef'),
            ]
        for net, hexc in codes:
            self.wif_encodings[net] = bytes.fromhex(hexc)
            self.wif_inverse[bytes.fromhex(hexc)] = net

    def address_prefix(self, scheme: str = 'P2PKH', network: str = 'mainnet'):
        '''
        '''
        myset = (scheme, network)
        if myset not in self.address_encodings:
            raise ValueError(
                'We have not implemented the address prefix for network: {}'.format(myset))
        return self.address_encodings[myset]


    def address_prefix_decode(self, code: bytes):
        '''
        '''
        if code not in self.address_inverse:
            raise ValueError(
                'Address prefix {} is not recognized'.format(code.hex()))
        return self.address_inverse[code]

    def wif_prefix(self, network: str = 'mainnet'):
        '''
        '''
        if network not in self.wif_encodings:
            raise ValueError(
                'We have not implemented the WIF prefix for network: {}'.format(network))
        return self.wif_encodings[network]


    def wif_prefix_decode(self, code: bytes):
        '''
        '''
        if code not in self.wif_inverse:
            raise ValueError(
                'WIF prefix {} is not recognized'.format(code.hex()))
        return self.wif_inverse[code]


    def hdwallet_prefix(self, key_type: str = 'priv', \
        scheme: str = 'P2PKH', network: str = 'mainnet'):
        """
        """
        myset = (key_type, scheme, network)

        if myset not in self.hdwallet_encodings:
            raise ValueError(
                'We have not implemented the HDWallet prefix for network: {}'.format(myset))
        return self.hdwallet_encodings[myset]

    def hdwallet_prefix_decode(self, code: bytes):
        """
        """
        if code not in self.hdwallet_inverse:
            raise ValueError(
                'HDWallet prefix {} is not recognized'.format(code.hex()))
        return self.hdwallet_inverse[code]


Network = Network_class()
