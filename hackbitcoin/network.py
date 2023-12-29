class Network:
    @staticmethod
    def p2pkh_prefix(network):
        if network=='mainnet':
            return b'\x00'
        elif network=='testnet':
            return b'\x6f'
        raise ValueError(
            'We have not implemented the address prefix for network: %s'
                % network)

    # BIP-13
    @staticmethod
    def p2sh_prefix(network):
        if network=='mainnet':
            return b'\x05'
        elif network=='testnet':
            return b'\xc4'
        raise ValueError(
            'We have not implemented the address prefix for network: %s'
                % network)


    @staticmethod
    def wif_prefix(network):
        if network=='mainnet':
            return b'\x80'
        elif network=='testnet':
            return b'\xef'
        raise ValueError(
            'We have not implemented the WIF prefix for network: %s'
                % network)

    @staticmethod
    def hdwallet_pub_prefix(network):
        if network=='mainnet':
            return bytes.fromhex('0488B21E')
        elif network=='testnet':
            return bytes.fromhex('043587CF')
        raise ValueError(
            'We have not implemented the HDWallet prefix for network: %s'
                % network)

    @staticmethod
    def hdwallet_priv_prefix(network):
        if network=='mainnet':
            return bytes.fromhex('0488ADE4')
        elif network=='testnet':
            return bytes.fromhex('04358394')
        raise ValueError(
            'We have not implemented the HDWallet prefix for network: %s'
                % network)

