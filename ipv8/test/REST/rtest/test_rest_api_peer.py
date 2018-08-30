import json
import logging
import os
import threading
from base64 import b64encode
from shutil import rmtree

from twisted.internet import reactor
from twisted.internet.defer import maybeDeferred, inlineCallbacks, returnValue
from twisted.internet.task import deferLater
from twisted.web import server

from ipv8_service import IPv8
from .peer_communication import GetStyleRequests, PostStyleRequests
from .rest_peer_communication import HTTPGetRequester, HTTPPostRequester, string_to_url
from ....REST.rest_manager import RESTRequest
from ....REST.root_endpoint import RootEndpoint
from ....attestation.identity.community import IdentityCommunity
from ....attestation.wallet.community import AttestationCommunity
from ....configuration import get_default_configuration
from ....keyvault.crypto import ECCrypto
from ....peer import Peer
from ....taskmanager import TaskManager

COMMUNITY_TO_MASTER_PEER_KEY = {
    'AttestationCommunity': ECCrypto().generate_key(u'high'),
    'DiscoveryCommunity': ECCrypto().generate_key(u'high'),
    'HiddenTunnelCommunity': ECCrypto().generate_key(u'high'),
    'IdentityCommunity': ECCrypto().generate_key(u'high'),
    'TrustChainCommunity': ECCrypto().generate_key(u'high'),
    'TunnelCommunity': ECCrypto().generate_key(u'high')
}


class TestPeer(object):
    """
    Class for the purpose of testing the REST API
    """

    def __init__(self, path, port, interface='127.0.0.1', configuration=None, other_verified_peers=None):
        """
        Create a test peer with a REST API interface.

        :param path: the for the working directory of this peer
        :param port: this peer's port
        :param interface: IP or alias of the peer. Defaults to '127.0.0.1'
        :param configuration: IPv8 configuration object. Defaults to None
        :param other_verified_peers: a list of TestPeer which will be immediately added as verified peers
        """
        self._logger = logging.getLogger(self.__class__.__name__)
        self._logger.info("Peer starting-up.")

        self._rest_manager = None

        self._port = port
        self._interface = interface

        self._path = path
        self._configuration = configuration

        # Check to see if we've received a custom configuration
        if configuration is None:
            # Create a default configuration
            self._configuration = get_default_configuration()

            self._configuration['logger'] = {'level': "ERROR"}

            overlays = ['AttestationCommunity', 'IdentityCommunity']
            self._configuration['overlays'] = [o for o in self._configuration['overlays'] if o['class'] in overlays]
            for o in self._configuration['overlays']:
                o['walkers'] = [{
                    'strategy': "RandomWalk",
                    'peers': 20,
                    'init': {
                        'timeout': 60.0
                    }
                }]

        self._create_working_directory(self._path)
        self._logger.info("Created working directory.")
        os.chdir(self._path)

        self._ipv8 = IPv8(self._configuration)
        os.chdir(os.path.dirname(__file__))

        # Change the master_peers of the IPv8 object's overlays, in order to avoid conflict with the live networks
        for idx, overlay in enumerate(self._ipv8.overlays):
            self._ipv8.overlays[idx].master_peer = Peer(COMMUNITY_TO_MASTER_PEER_KEY[type(overlay).__name__])

        self._rest_manager = TestPeer.RestAPITestWrapper(self._ipv8, self._port, self._interface)
        self._rest_manager.start()
        self._logger.info("Peer started up.")

        # If available, add the verified peers
        if other_verified_peers is not None:
            self.add_and_verify_peers(other_verified_peers)

    def print_master_peers(self):
        """
        Print details on the master peers of each of this peer's overlays

        :return: None
        """
        for overlay in self._ipv8.overlays:
            print b64encode(overlay.master_peer.mid), overlay.master_peer.public_key, overlay.master_peer.address, \
                overlay.master_peer.key.pub().key_to_bin().encode("HEX")

    def get_address(self):
        """
        Return the address of this peer

        :return: A tuple[str, int] representing the address of this peer (i.e. the interface and port)
        """
        return self._ipv8.endpoint.get_address()

    def add_and_verify_peers(self, peers, replace_default_interface=True):
        """
        Add a set of peers to the set of verified peers and register their services

        :param peers: a list of peers of the type TestPeer
        :param replace_default_interface: if True, replaces the '0.0.0.0' all broadcast interface to the 'localhost'
        :return: None
        """
        assert peers is not None and isinstance(peers, list), "peers must be a non-empty list"
        assert all(isinstance(x, TestPeer) for x in peers), "All peers must be of the TestPeer type"

        for peer in peers:
            interface, port = peer.get_address()

            if interface == '0.0.0.0' and replace_default_interface:
                for inner_peers in peer.get_keys().values():
                    self.add_and_verify_peer(inner_peers, port=port)
            else:
                for inner_peers in peer.get_keys().values():
                    self.add_and_verify_peer(inner_peers, interface, port)

    def add_and_verify_peer(self, peer, interface='127.0.0.1', port=8090):
        """
        Add a set of peers to the set of verified peers and register their services

        :param peer: the peer to be added
        :param interface: the peer's interface
        :param port: the peer's REST API port
        :return: None
        """
        self._ipv8.network.add_verified_peer(peer)
        self._ipv8.network.discover_services(peer, [overlay.master_peer.mid for overlay in self._ipv8.overlays])
        self._ipv8.network.discover_address(peer, (interface, port))

    def add_verified_peer(self, peer):
        """
        Add a new verified peer

        :param peer: the new peer
        :return: None
        """
        self._ipv8.network.add_verified_peer(peer)

    def add_peer_to_all_services(self, peer):
        """
        Add a pier to the identity service

        :param peer: the peer to be added to the identity service
        :return: None
        """
        self._ipv8.network.discover_services(peer, [overlay.master_peer.mid for overlay in self._ipv8.overlays])

    def add_peer_address(self, peer, interface, port):
        """
        Add the address of a peer so it becomes accessible

        :param peer: the peer whose address will be added
        :param interface: The interface (IP or alias) of the peer
        :param port: The port on which the peer accepts requests
        :return: None
        """
        self._ipv8.network.discover_address(peer, (interface, port))

    def stop(self):
        """
        Stop the peer

        :return: None
        """
        self._logger.info("Shutting down the peer")
        self._ipv8.endpoint.close()
        self._rest_manager.shutdown_task_manager()
        self._rest_manager.stop()

        # Close the DBs of some of the communities
        for overlay in self._ipv8.overlays:
            if isinstance(overlay, AttestationCommunity):
                overlay.database.close()
            elif isinstance(overlay, IdentityCommunity):
                overlay.persistence.close()

        if os.path.isdir(self._path):
            rmtree(self._path, ignore_errors=True)

    @staticmethod
    def _create_working_directory(path):
        """
        Creates a dir at the specified path, if not previously there; otherwise deletes the dir, and makes a new one.

        :param path: the location at which the dir is created
        :return: None
        """
        if os.path.isdir(path):
            rmtree(path)
        os.mkdir(path)

    def get_keys(self):
        """
        Get the peer's keys

        :return: the peer's keys
        """
        self._logger.info("Fetching my IPv8 object's peer.")
        return self._ipv8.keys

    def get_mids(self, replace_characters=True):
        """
        Return a list of the b64 encoded mids of this peer

        :param replace_characters: a boolean variable, which indicates whether certain characters which cannot
                                  be forwarded within an HTTP request should be replaced
        :return: a list of the peer's mids (encoded in b64)
        """
        if replace_characters:
            return [string_to_url(b64encode(x.mid)) for x in self._ipv8.keys.values()]

        return [b64encode(x.mid) for x in self._ipv8.keys.values()]

    def get_mid_by_key(self, key='my peer'):
        """
        Return a mid given a key which identifies one of this peer's identity

        :param key: the key supplied. By default 'my peer'
        :return: the chosen mid
        """
        return string_to_url(b64encode(self._ipv8.keys[key].mid)) if key in self._ipv8.keys else ''

    def get_overlay_by_name(self, name):
        """
        Get one of the peer's overlays as identified by its name

        :parameter name: the name of the overlay
        :return: the peer's overlays
        """
        self._logger.info("Fetching my IPv8 object's overlay: %s", name)
        for overlay in self._ipv8.overlays:
            if type(overlay).__name__ == name:
                return overlay

        return None

    @property
    def port(self):
        return self._port

    @property
    def interface(self):
        return self._interface

    class RestAPITestWrapper(TaskManager):
        """
        This class is responsible for managing the startup and closing of the HTTP API.
        """

        def __init__(self, session, port=8085, interface='127.0.0.1'):
            """
            Creates a TaskManager object for REST API testing purposes

            :param session: an (IPv8) session object.
            :param port: this peer's port. Defaults to 8085
            :param interface: IP or alias of the peer. Defaults to '127.0.0.1'
            """
            super(TestPeer.RestAPITestWrapper, self).__init__()
            self._logger = logging.getLogger(self.__class__.__name__)
            self._session = session
            self._site = None
            self._root_endpoint = None
            self._port = port
            self._interface = interface

        def start(self):
            """
            Starts the HTTP API with the listen port as specified in the session configuration.
            """
            self._root_endpoint = RootEndpoint(self._session)
            self._site = server.Site(resource=self._root_endpoint)
            self._site.requestFactory = RESTRequest
            self._site = reactor.listenTCP(self._port, self._site, interface=self._interface)

        def stop(self):
            """
            Stop the HTTP API and return a deferred that fires when the server has shut down.
            """
            return maybeDeferred(self._site.stopListening)

        def get_access_parameters(self):
            """
            Creates a dictionary of parameters used to access the peer

            :return: the dictionary of parameters used to access the peer
            """
            return {
                'port': self._port,
                'interface': self._interface,
                'url': 'http://{0}:{1}/attestation'.format(self._interface, self._port)
            }


class InteractiveTestPeer(TestPeer, threading.Thread):
    """
    This class models the basic behavior of simple peer instances which are used for interaction. Subclasses should
    implement the actual main logic of the peer in the run() method (from Thread).
    """

    def __init__(self, path, port, interface='127.0.0.1', configuration=None, get_style_requests=None,
                 post_style_requests=None, other_verified_peers=None):
        """
        InteractiveTestPeer initializer

        :param path: the for the working directory of this peer
        :param port: this peer's port
        :param interface: IP or alias of the peer. Defaults to '127.0.0.1'
        :param configuration: IPv8 configuration object. Defaults to None
        :param get_style_requests: GET style request generator. Defaults to None
        :param post_style_requests: POST style request generator. Defaults to None
        :param other_verified_peers: a list of TestPeer which will be immediately added as verified peers
        """
        assert get_style_requests is None or isinstance(get_style_requests, GetStyleRequests), \
            "The get_style_requests parameter must be a subclass of GetStyleRequests"
        assert post_style_requests is None or isinstance(post_style_requests, PostStyleRequests), \
            "The post_style_requests parameter must be a subclass of PostStyleRequests"

        TestPeer.__init__(self, path, port, interface, configuration, other_verified_peers)
        threading.Thread.__init__(self)

        # Check to see if the user has provided request generators
        self._get_style_requests = get_style_requests if get_style_requests is not None else HTTPGetRequester()
        self._post_style_requests = post_style_requests if post_style_requests is not None else HTTPPostRequester()

        self._logger.info("Successfully acquired request generators.")

    @inlineCallbacks
    def wait_for_peers(self, dict_param, excluded_peer_mids=None):
        """
        Wait until this peer receives a non-empty list of fellow peers in the network

        :param dict_param: the required parameters by the GET request generator for the peers request type
        :param excluded_peer_mids: A list of peer mids which should not be taken into consideration peers
        :return: a list of currently known peers in the network
        """
        assert isinstance(excluded_peer_mids, (list, set)) or not excluded_peer_mids, "excluded_peer_mids " \
                                                                                      "must be a list or set or None"

        # Make sure excluded_peer_mids is a set
        if not excluded_peer_mids:
            excluded_peer_mids = set()
        elif isinstance(excluded_peer_mids, list):
            excluded_peer_mids = set(excluded_peer_mids)

        peer_list = yield self._get_style_requests.make_peers(dict_param)
        peer_list = set(json.loads(peer_list))

        # Keep iterating until peer_list is non-empty
        while not peer_list - excluded_peer_mids:
            yield deferLater(reactor, 0.1, lambda: None)

            # Forward and wait for the response
            peer_list = yield self._get_style_requests.make_peers(dict_param)
            peer_list = set(json.loads(peer_list))

        # Return the peer list
        returnValue(list(peer_list - excluded_peer_mids))

    @inlineCallbacks
    def wait_for_attestation_request(self, dict_param):
        """
        Wait until this peer receives a non-empty list of outstanding attestation requests

        :param dict_param: the required parameters by the GET request generator for the outstanding request type
        :return: a list of outstanding attestation requests
        """
        self._logger.info("Attempting to acquire a list of outstanding requests...")
        outstanding_requests = yield self._get_style_requests.make_outstanding(dict_param)

        # Keep iterating until peer_list is non-empty
        while outstanding_requests == "[]":
            self._logger.info("Could not acquire a list of outstanding requests. Will wait 0.1 seconds and retry.")
            yield deferLater(reactor, 0.1, lambda: None)

            # Forward and wait for the response
            outstanding_requests = yield self._get_style_requests.make_outstanding(dict_param)

        # Return the peer list
        self._logger.info("Have found a non-empty list of outstanding requests. Returning it.")
        returnValue(outstanding_requests)
