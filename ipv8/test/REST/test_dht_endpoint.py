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
from ...messaging.serialization import Serializer


class TestDHTEndpoint(RESTTestBase):
    """
    Class for testing the DHT Endpoint in the REST API of the IPv8 object
    """

    def setUp(self):
        super(TestDHTEndpoint, self).setUp()
        self.initialize([(2, TestPeer)])

        self.serializer = Serializer()

    @inlineCallbacks
    def publish_to_DHT(self, peer, key, data, numeric_version):
        """
        Publish data to the DHT via a peer

        :param peer: the peer via which the data is published to the DHT
        :param key: the key of the added data
        :param data: the data itself; should be a string
        :param numeric_version: the version of the data
        :return: None
        """
        version = struct.pack("H", numeric_version)

        for i in range(0, len(data), MAX_ENTRY_SIZE - 3):
            blob_chunk = version + data[i:i + MAX_ENTRY_SIZE - 3]
            yield peer.get_overlay_by_class(DHTCommunity).store_value(key, blob_chunk)

    def deserialize_payload(self, serializables, data):
        """
        Deserialize data

        :param serializables: the list of serializable formats
        :param data: the serialized data
        :return: The payload obtained from deserializing the data
        """
        payload = self.serializer.unpack_to_serializables(serializables, data)
        return payload[:-1][0]

    @inlineCallbacks
    def test_added_block_explicit(self):
        """
        Test the publication of a block which has been added by hand to the DHT
        """
        param_dict = {
            'port': self.peer_list[0].port,
            'interface': self.peer_list[0].interface,
            'endpoint': 'dht/block',
            'public_key': string_to_url(b64encode(self.peer_list[0].get_keys()['my_peer'].mid))
        }
        # Introduce the nodes
        yield self.introduce_nodes(DHTCommunity)

        # Manually add a block to the Trustchain
        original_block = TestBlock()
        hash_key = sha1(self.peer_list[0].get_keys()['my_peer'].mid + DHTBlockEndpoint.KEY_SUFFIX).digest()

        yield self.publish_to_DHT(self.peer_list[0], hash_key, original_block.pack(), 4536)

        # Get the block through the REST API
        response = yield self._get_style_requests.make_dht_block(param_dict)
        self.assertTrue(b'block' in response and response[b'block'], "Response is not as expected: {}".format(response))
        response = b64decode(response[b'block'])

        # Reconstruct the block from what was received in the response
        payload = self.deserialize_payload((HalfBlockPayload, ), response)
        reconstructed_block = self.peer_list[0].get_overlay_by_class(TrustChainCommunity).get_block_class(payload.type)\
            .from_payload(payload, self.serializer)

        self.assertEqual(reconstructed_block, original_block, "The received block was not the one which was expected")

    @inlineCallbacks
    def test_added_block_implicit(self):
        """
        Test the publication of a block which has been added implicitly to the DHT
        """
        param_dict = {
            'port': self.peer_list[1].port,
            'interface': self.peer_list[1].interface,
            'endpoint': 'dht/block',
            'public_key': string_to_url(b64encode(self.peer_list[0].get_keys()['my_peer'].mid))
        }
        # Introduce the nodes
        yield self.introduce_nodes(DHTCommunity)

        publisher_pk = self.peer_list[0].get_overlay_by_class(TrustChainCommunity).my_peer.public_key.key_to_bin()

        yield self.peer_list[0].get_overlay_by_class(TrustChainCommunity).create_source_block(b'test', {})
        original_block = self.peer_list[0].get_overlay_by_class(TrustChainCommunity).persistence.get(publisher_pk, 1)
        yield self.deliver_messages()

        # Get the block through the REST API
        response = yield self._get_style_requests.make_dht_block(param_dict)
        self.assertTrue(b'block' in response and response[b'block'], "Response is not as expected: {}".format(response))
        response = b64decode(response[b'block'])

        # Reconstruct the block from what was received in the response
        payload = self.deserialize_payload((HalfBlockPayload,), response)
        reconstructed_block = self.peer_list[0].get_overlay_by_class(TrustChainCommunity).get_block_class(payload.type)\
            .from_payload(payload, self.serializer)

        self.assertEqual(reconstructed_block, original_block, "The received block was not the one which was expected")
