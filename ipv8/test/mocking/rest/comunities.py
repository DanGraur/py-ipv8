from ....attestation.identity.community import IdentityCommunity
from ....attestation.wallet.community import AttestationCommunity
from ....attestation.trustchain.community import TrustChainCommunity
from ....dht.community import DHTCommunity
from ....keyvault.crypto import ECCrypto
from ....peer import Peer


class TestAttestationCommunity(AttestationCommunity):
    master_peer = Peer(ECCrypto().generate_key(u'high'))


class TestIdentityCommunity(IdentityCommunity):
    master_peer = Peer(ECCrypto().generate_key(u'high'))


class TestDHTCommunity(DHTCommunity):
    master_peer = Peer(ECCrypto().generate_key(u'high'))


class TestTrustchainCommunity(TrustChainCommunity):
    master_peer = Peer(ECCrypto().generate_key(u'high'))
