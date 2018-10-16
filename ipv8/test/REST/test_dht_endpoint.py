import struct

from hashlib import sha1
from base64 import b64encode, b64decode
from twisted.internet.defer import inlineCallbacks

from ..attestation.trustchain.test_block import TestBlock
from ..mocking.rest.base import RESTTestBase
from ..mocking.rest.rest_peer_communication import string_to_url
from ..mocking.rest.rest_api_peer import TestPeer
from ...attestation.trustchain.payload import HalfBlockPayload
from ...attestation.trustchain.community import TrustChainCommunity
from ...dht.community import DHTCommunity, MAX_ENTRY_SIZE
from ...REST.dht_endpoint import DHTBlockEndpoint


class TestDHTEndpoint(RESTTestBase):
    """
    Class for testing the DHT Endpoint in the REST API of the IPv8 object
    """

    def setUp(self):
        super(TestDHTEndpoint, self).setUp()
        self.initialize([(5, TestPeer)])

    @inlineCallbacks
    def test_added_block(self):
        param_dict = {
            'port': self.peer_list[0].port,
            'interface': self.peer_list[0].interface,
            'endpoint': 'dht/block',
            'public_key': string_to_url(b64encode(self.peer_list[0].get_keys()['my_peer'].mid))
        }
        yield self.introduce_nodes(DHTCommunity)

        # Manually add a block to the Trustchain
        original_block = TestBlock()
        packed_block = original_block.pack()
        version = struct.pack("H", 4536)
        hash_key = sha1(self.peer_list[0].get_keys()['my_peer'].mid + DHTBlockEndpoint.KEY_SUFFIX).hexdigest()

        for i in range(0, len(packed_block), MAX_ENTRY_SIZE - 3):
            blob_chunk = version + packed_block[i:i + MAX_ENTRY_SIZE - 3]
            yield self.peer_list[0].get_overlay_by_class(DHTCommunity).store_value(hash_key, blob_chunk)

        res = self.peer_list[0].get_overlay_by_class(DHTCommunity).storage.get(hash_key)
        print "Home ", res
        res = self.peer_list[1].get_overlay_by_class(DHTCommunity).storage.get(hash_key)
        print "Home ", res

        # return

        # Get the block through the REST API
        response = yield self._get_style_requests.make_dht_block(param_dict)
        self.assertTrue(b'block' in response and response[b'block'], "Response is not as expected: {}".format(response))
        response = b64decode(response[b'block'])

        # Reconstruct the block from what was received in the response
        payload = self.peer_list[0].get_overlay_by_class(DHTCommunity).serializer\
            .unpack_to_serializables((HalfBlockPayload, ), response)
        payload = payload[:-1][0]
        reconstructed_block = self.peer_list[0].get_overlay_by_class(TrustChainCommunity).get_block_class(payload.type)\
            .from_payload(payload, self.peer_list[0].get_overlay_by_class(TrustChainCommunity).serializer)

        self.assertEqual(reconstructed_block, original_block, "The received block was not the one which was expected")
