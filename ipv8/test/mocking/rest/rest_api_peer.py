import logging
import threading
from base64 import b64encode

from twisted.internet import reactor
from twisted.internet.defer import inlineCallbacks, returnValue, maybeDeferred
from twisted.internet.task import deferLater
from twisted.web import server

from .peer_communication import GetStyleRequests, PostStyleRequests
from .rest_peer_communication import HTTPGetRequester, HTTPPostRequester, string_to_url
from .ipv8 import TestIPv8
from ....REST.rest_manager import RESTRequest
from ....REST.root_endpoint import RootEndpoint
from ....taskmanager import TaskManager


class TestPeer(object):
    """
    Class for the purpose of testing the REST API
    """

    def __init__(self, port, interface='127.0.0.1', other_verified_peers=None, memory_dbs=True):
        """
        Create a test peer with a REST API interface. All subclasses of this class should maintain path and port as
        the first and second argument in the initializer method.

        :param port: this peer's port
        :param interface: IP or alias of the peer. Defaults to '127.0.0.1'
        :param other_verified_peers: a list of TestPeer which will be immediately added as verified peers
        """
        self._logger = logging.getLogger(self.__class__.__name__)
        self._logger.info("Peer starting-up.")

        self._rest_manager = None

        self._port = port
        self._interface = interface

        self._ipv8 = TestIPv8(u'curve25519', port, interface, memory_dbs)

        self._rest_manager = TestPeer.RestAPITestWrapper(self._ipv8, self._port, self._interface)
        self._rest_manager.start()
        self._logger.info("Peer started up.")

        # If available, add the verified peers
        if other_verified_peers is not None:
            self.add_and_verify_peers(other_verified_peers)

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

    def close(self):
        """
        Stop the peer

        :return: None
        """
        self._logger.info("Shutting down the peer")

        self._rest_manager.stop()
        self._rest_manager.shutdown_task_manager()

        self._ipv8.unload()

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
            return [b64encode(x.mid) for x in self._ipv8.keys.values()]

        return [b64encode(x.mid) for x in self._ipv8.keys.values()]

    def get_mid_by_key(self, key='my peer'):
        """
        Return a mid given a key which identifies one of this peer's identity

        :param key: the key supplied. By default 'my peer'
        :return: the chosen mid
        """
        return string_to_url(b64encode(self._ipv8.keys[key].mid)) if key in self._ipv8.keys else ''

    def get_overlay_by_class(self, name):
        """
        Get one of the peer's overlays as identified by its name

        :parameter name: the name of the overlay
        :return: the peer's overlays
        """
        self._logger.info("Fetching my IPv8 object's overlay: %s", name)
        for overlay in self._ipv8.overlays:
            if isinstance(overlay, name):
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
            self._site_port = None
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
            self._site_port = reactor.listenTCP(self._port, self._site, interface=self._interface)

        def stop(self):
            """
            Stop the HTTP API and return a deferred that fires when the server has shut down.
            """
            self._site.stopFactory()
            return maybeDeferred(self._site_port.stopListening)

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

    def __init__(self, port, interface='127.0.0.1', memory_dbs=True, get_style_requests=None, post_style_requests=None,
                 other_verified_peers=None):
        """
        InteractiveTestPeer initializer

        :param port: this peer's port
        :param interface: IP or alias of the peer. Defaults to '127.0.0.1'
        :param get_style_requests: GET style request generator. Defaults to None
        :param post_style_requests: POST style request generator. Defaults to None
        :param other_verified_peers: a list of TestPeer which will be immediately added as verified peers
        :param memory_dbs: if True, then the DBs of the various overlays / communities are stored in memory; on disk
                           if False
        """
        assert get_style_requests is None or isinstance(get_style_requests, GetStyleRequests), \
            "The get_style_requests parameter must be a subclass of GetStyleRequests"
        assert post_style_requests is None or isinstance(post_style_requests, PostStyleRequests), \
            "The post_style_requests parameter must be a subclass of PostStyleRequests"

        TestPeer.__init__(self, port, interface, other_verified_peers, memory_dbs)
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
        peer_list = set(peer_list)

        # Keep iterating until peer_list is non-empty
        while not peer_list - excluded_peer_mids:
            yield deferLater(reactor, 0.1, lambda: None)

            # Forward and wait for the response
            peer_list = yield self._get_style_requests.make_peers(dict_param)
            peer_list = set(peer_list)

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
        while not outstanding_requests:
            self._logger.info("Could not acquire a list of outstanding requests. Will wait 0.1 seconds and retry.")
            yield deferLater(reactor, 0.1, lambda: None)

            # Forward and wait for the response
            outstanding_requests = yield self._get_style_requests.make_outstanding(dict_param)

        # Return the peer list
        self._logger.info("Have found a non-empty list of outstanding requests. Returning it.")
        returnValue(outstanding_requests)
