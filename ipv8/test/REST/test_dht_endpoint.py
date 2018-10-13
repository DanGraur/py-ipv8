from base64 import b64encode
from twisted.internet.defer import inlineCallbacks

from ..mocking.rest.base import RESTTestBase
from ..mocking.rest.comunities import TestTrustchainCommunity
from ..mocking.rest.peer_interactive_behavior import AndroidTestPeer
from ..mocking.rest.rest_peer_communication import string_to_url
from ..mocking.rest.rest_api_peer import TestPeer


class TestAttestationEndpoint(RESTTestBase):
    """
    Class for testing the DHT Endpoint in the REST API of the IPv8 object
    """

    def setUp(self):
        super(TestAttestationEndpoint, self).setUp()
        self.initialize([(1, TestPeer)])

    @inlineCallbacks
    def test_added_block(self):
        param_dict = {
            'port': self.peer_list[0].port,
            'interface': self.peer_list[0].interface,
            'endpoint': 'dht/block',
            'public_key': string_to_url(b64encode(self.peer_list[0].get_keys()['my_peer'].mid))
        }

        print param_dict['public_key']

        # Add a block to the trustchain
        # self.peer_list[0].get_overlay_by_class(TestTrustchainCommunity).persistence.add_block(block1)
        self.peer_list[0].get_overlay_by_class(TestTrustchainCommunity).create_source_block(b'test', {})

        response = yield self._get_style_requests.make_dht_block(param_dict)
        #
        print response
