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
