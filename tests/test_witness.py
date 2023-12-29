import pytest
from io import BytesIO

from .context import hackbitcoin
from hackbitcoin.witness import Witness
from hackbitcoin.transaction import Tx

def hex_to_stream(hexstr):
    return BytesIO(bytes.fromhex(hexstr))

def test_witness():
    rawtx = '02000000000102d01e41be1422dbfcc317ac828f1b2916d280ad05a6f3fb851589df70d07448be0100000000ffffffff2702105dd5917ce7f6b19386ee0971e376793e217dbec9de348e0c182e7cc3f40100000000ffffffff02ec4d01000000000017a9140c0daaea89d81baf3bb54deece685cf49707a96f87eae10000000000001600143dda20e6bb734df7559a56d92955a8a4db07b6b002483045022100ce6ef2681ade97f1a6b459f7d9389ed892123b541dcce3c2f15831bb8f4b3e6702205e7cf355ccdfaa12131e4ea4187d0f86ffb95d332857f043c9f329fcbdaa386e012102f39acb1bef5095f0fb8864b4799192f0c644f2bda6cfbb99d1c337948db9c9c502483045022100d8d8256078a94a3df6bff4b3b0e412057499b0750d848d4a69310ec276dffb85022071affd28062cabcaeebd0a9e432aa93e3793756483c5530377886e7eca14ae0601210355fb0a177edf38d2bcb0a4982ebbd9acb1345d3c080a4fbd547d3e23ff63e5a600000000'

    tx = Tx.parse(hex_to_stream(rawtx))
    assert tx.version==2
    assert tx.txid()=='5967008cd7572a2c368192809bab6d0b07454a78291e35f2dfbcc0cd642dfbb9'
    assert tx.hash().hex()=='2d38762cd266af3440ae60193ea3b749f4f9df26b1cc8f2b133f5d90d7e57ad4'
    assert tx.size()==373
    assert tx.vsize()==210
    assert tx.weight()==838
    assert len(tx.tx_ins) == 2
    assert len(tx.tx_outs) == 2
    assert tx.is_segwit()==True

    assert tx.witness.serialize().hex()=='02483045022100ce6ef2681ade97f1a6b459f7d9389ed892123b541dcce3c2f15831bb8f4b3e6702205e7cf355ccdfaa12131e4ea4187d0f86ffb95d332857f043c9f329fcbdaa386e012102f39acb1bef5095f0fb8864b4799192f0c644f2bda6cfbb99d1c337948db9c9c502483045022100d8d8256078a94a3df6bff4b3b0e412057499b0750d848d4a69310ec276dffb85022071affd28062cabcaeebd0a9e432aa93e3793756483c5530377886e7eca14ae0601210355fb0a177edf38d2bcb0a4982ebbd9acb1345d3c080a4fbd547d3e23ff63e5a6'
