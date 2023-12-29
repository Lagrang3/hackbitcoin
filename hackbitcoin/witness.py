from .varint import varint

class Witness:
    WITNESS_SCALE_FACTOR=4

    def __init__(self,wFields=[]):
        self.wFields = wFields

    @classmethod
    def parse(cls,stream,nTXin):
        """
        stream: data stream, supports `read` function
        nTXin: number of inputs in the transaction
        """
        # BIP141:
        # - for each txin there is a witness field
        # - each witness field can contain several witness data
        # - witness is not script
        wFields = []
        for i in range(nTXin):
            items = []
            length = varint.parse(stream)
            for n in range(length):
                size = varint.parse(stream)
                wData = stream.read(size)
                items.append(wData)
            wFields.append(items)
        return cls(wFields)


    def serialize(self):
        raw = b''
        for items in self.wFields:
            raw += varint.encode(len(items))
            for data in items:
                raw += varint.encode(len(data))
                raw += data
        return raw

