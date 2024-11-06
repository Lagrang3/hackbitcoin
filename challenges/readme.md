# Transaction explorer

1. Get the txid of the first bitcoin transaction (not coinbase).

# Private keys and addresses

Someone claims stolen funds from some bitcoin address are theirs.
They provide a message and a signature.
address: `bc1qn3d7vyks0k3fx38xkxazpep8830ttmydwekrnl`
message: `@83_5BTC is the owner of the funds that paid the high fee`
signature: `H2eqkv/w1BmTXxeVhnFNcjoR3di9Kfzp9eh8Q5mEzwjQelQPtfXgtpKCwlocQcqBmRkzJ6ZBHWtsIO5OtqSmAXo=`

1. Check if the signature is valid.

# Private keys and addresses

1. Create a private key using this data `0xdeadbeef`.
2. Create two testnet bitcoin addresses A uncompressed and B compressed.
3. Get some testnet coins from a faucet and send them to A and B.
4. Create a single transaction that spends the previous coins back to the
   faucet.

# Fake signatures
https://bitcoin.stackexchange.com/questions/81115/if-someone-wanted-to-pretend-to-be-satoshi-by-posting-a-fake-signature-to-defrau

1. Find one of Satoshi's public keys (from the famous first Bitcoin
   transaction).
2. Produce a fake signature.
3. Verify it.

#  Private key leak

1. Create a private key using this data `0xdeadbeef`.
2. Sign two messages: `my first message`, `my second message` with the same key
   and the same secret nounce.
3. Verify the signatures and deduce the initial private key from the two signatures.
4. Given two messages signed with the same private key, can we check if both
   were signed with the same nounce.
5. (advanced) scan the entire blockchain and try to steal private keys using
   this method.

# Vanity addresses

1. Create a vanity address

# Segwit address

# Taproot address

# (Advanced) Anti-exfil signatures

# Rolling dice

1. Generate the first 10 addresses from a dice roll entropy generator

2. scan poor entropy addresses for balance in the network.

# Amount overflow

Create a transaction that uses C++ overflow so that for any given set of inputs
it produces an initially desired output plus change.

see `https://en.bitcoin.it/wiki/Value_overflow_incident`

# BIP39

Given a mnemonic sentence incomplete by a word, return a valid sentence.


# Bitcoin puzzle

https://privatekeyfinder.io/bitcoin-puzzle

In December 2015 someone posted
https://bitcointalk.org/index.php?topic=1305887.0
to have been brute forcing private keys for fun.

Some days later he had discovered
https://bitcointalk.org/index.php?topic=1306983
that some low value private keys correspond to the bitcoin addresses
in the output of a misterious transaction broadcasted in January 2015
tx/08389f34c98c606322740c0be6a7125d9860bb8d5cb182c02f98461e5fa6cd15

It seems that someone has put up to 32BTC in 256 outputs with
increasing entropy.
The conjeture is that the k-th output goes to a private key
in the range [2^{k-1},2^k), ie. search space size of 2^{k-1}

eg.
k = 1, [1,2) , price 0.001 BTC, solution 1
k = 2, [2, 4) , price 0.002 BTC, solution 3
k = 3, [4, 8) , price 0.003 BTC, solution 7
...

notice 0.001 BTC x sum_{i=1 to 256} i = 32.896 BTC

A valid signature to spend those bitcoin has to come from a public key that
hashes to the correct ripemd160, thus in practice there is no need to up to
256 bits search to claim all outputs but in theory up to 160 bits in
private key space until all possible hashes have been found.
That's why a further transaction from the puzzle master in 2017
tx/5d45587cfd1d5b0fb826805541da7d94c61fe432259e68ee26f4a04544384164
redistributed the price from outputs 161 to 256 among the puzzle addresses
that to that point remained unsolved adding also some additional 84 BTC to the
price pool.

In 2019
tx/7c432398c7631600af01695c9767eff109cbfae4f7ecccaff388043a474d4f1e
probably the puzzle master again sent additional 0.001 BTC and distributed it
among the 65th, 70th, 75th, ... and 160th addresses for later spend all of them
some days later
tx/17e4e323cfbc68d7f0071cad09364e8193eedf8fefbcbd8a21b4b65717a4b3d3
doing this the puzzle master revealed the public keys (and not just their hashes)
thus reducing the difficulty of finding those private keys.

In 2023 someone has rebumped the price of the remaining hidden keys by 872 BTC
tx/12f34b58b04dfb0233ce889f674781c0e0c7ba95482cca469125af41a78d13b3
