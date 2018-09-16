import json
from base64 import b64encode

from twisted.internet import reactor
from twisted.internet.defer import inlineCallbacks
from twisted.internet.task import deferLater

from .test_rest_api_peer import InteractiveTestPeer
from .rest_peer_communication import string_to_url


class AndroidTestPeer(InteractiveTestPeer):
    """
    Simulates the android application
    """

    def __init__(self, path, port, param_dict, interface='127.0.0.1', configuration=None, get_style_requests=None,
                 post_style_requests=None, other_verified_peers=None):
        """
        AndroidTestPeer initializer

        :param path: the for the working directory of this peer
        :param port: this peer's port
        :param param_dict: a dictionary containing the required parameters to communicate with a peer
        :param interface: IP or alias of the peer. Defaults to '127.0.0.1'
        :param configuration: IPv8 configuration object. Defaults to None
        :param get_style_requests: GET style request generator. Defaults to None
        :param post_style_requests: POST style request generator. Defaults to None
        :param other_verified_peers: a list of TestPeer which will be immediately added as verified peers
        """
        InteractiveTestPeer.__init__(self, path=path, port=port, interface=interface, configuration=configuration,
                                     get_style_requests=get_style_requests, post_style_requests=post_style_requests,
                                     other_verified_peers=other_verified_peers)

        self._param_dict = param_dict
        self._param_dict['port'] = port
        self._param_dict['attribute_value'] = string_to_url(b64encode('binarydata'), True)
        self._param_dict['metadata'] = b64encode(json.dumps({'psn': '1234567890'}))

    @inlineCallbacks
    def run(self):
        # Wait for a short period of time
        yield deferLater(reactor, 1, lambda: None)

        peer_list = yield self.wait_for_peers(self._param_dict)

        for peer in peer_list:
            self._param_dict['mid'] = string_to_url(peer)

            self._logger.info("Sending an attestation request to %s", self._param_dict['mid'])
            yield self._post_style_requests.make_attestation_request(self._param_dict)


class MinimalActivityTestPeer(InteractiveTestPeer):
    """
    Simulates a minimal activity test peer, which only attempts to discover fellow peers then goes inactive
    """

    def __init__(self, path, port, param_dict, interface='127.0.0.1', configuration=None, get_style_requests=None,
                 other_verified_peers=None):
        """
        MinimalActivityTestPeer initializer

        :param path: the for the working directory of this peer
        :param port: this peer's port
        :param param_dict: a dictionary containing the required parameters to communicate with a peer
        :param interface: IP or alias of the peer. Defaults to '127.0.0.1'
        :param configuration: IPv8 configuration object. Defaults to None
        :param get_style_requests: GET style request generator. Defaults to None
        :param other_verified_peers: a list of TestPeer which will be immediately added as verified peers
        """
        InteractiveTestPeer.__init__(self, path=path, port=port, interface=interface, configuration=configuration,
                                     get_style_requests=get_style_requests, other_verified_peers=other_verified_peers)

        self._param_dict = param_dict
        self._param_dict['port'] = port

    @inlineCallbacks
    def run(self):
        # Wait for a short period of time
        yield deferLater(reactor, 1, lambda: None)

        # Await for some fellow peers, then become inactive
        yield self.wait_for_peers(self._param_dict)
