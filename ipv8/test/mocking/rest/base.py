import os
from random import choice
from shutil import rmtree
from string import ascii_uppercase, digits
from threading import Thread

from twisted.internet.task import deferLater
from twisted.trial import unittest
from twisted.internet import reactor
from twisted.internet.defer import inlineCallbacks

from .peer_communication import GetStyleRequests, PostStyleRequests
from .rest_peer_communication import HTTPGetRequester, HTTPPostRequester
from .rest_api_peer import TestPeer

TEST_FOLDER_PREFIX = "test_temp"


class RESTTestBase(unittest.TestCase):

    other_peer_port = 7868

    def __init__(self, methodName='runTest'):
        super(RESTTestBase, self).__init__(methodName)

        self.peer_list = []
        self.working_dirs = set([])

        self._get_style_requests = None
        self._post_style_requests = None

    def initialize(self, peer_configurations, get_style_requests=None, post_style_requests=None):
        """
        Initialize this test by instantiating some peers

        :param peer_configurations: a list o tuples of the form (int, <? extends TestPeer>); each tuple will initialize
                                    as many peers of the type in the second element as in the first element
        :param get_style_requests: GET style request generator. Defaults to None.
        :param post_style_requests: POST style request generator. Defaults to None.
        :return: None
        """
        assert isinstance(peer_configurations, list), "peer_configurations must be a list"
        assert all(isinstance(x[0], int) and issubclass(x[1], TestPeer) for x in peer_configurations), \
            "peer_configurations not properly structured"
        assert get_style_requests is None or isinstance(get_style_requests, GetStyleRequests), \
            "The get_style_requests parameter must be a subclass of GetStyleRequests"
        assert post_style_requests is None or isinstance(post_style_requests, PostStyleRequests), \
            "The post_style_requests parameter must be a subclass of PostStyleRequests"

        for count, peer_type in peer_configurations:
            for _ in range(count):
                self.create_new_peer(peer_type, None)

        self._get_style_requests = get_style_requests if get_style_requests is not None else HTTPGetRequester()
        self._post_style_requests = post_style_requests if post_style_requests is not None else HTTPPostRequester()

    def setUp(self):
        super(RESTTestBase, self).setUp()

        self.peer_list = []
        self.working_dirs = set([])

    def tearDown(self):
        self.gracefully_terminate_peers()
        while self.working_dirs:
            rmtree(self.working_dirs.pop())

        super(RESTTestBase, self).tearDown()

    def create_new_peer(self, peer_cls, port, *args, **kwargs):
        """
        Create and return a new peer for testing.

        :param peer_cls: specifies the test class of the new peer
        :param port: the port of the peer mai be optionally provided, however, this is not advised as it might overlap
                     with an existing peer. Thus, it should be set to None. In this case, the port will be chosen by
                     this method.
        :param args: peer arguments (not considering the path and port)
        :param kwargs: keyworded peer arguments
        :return: the newly created peer and its index in the peer list
        """
        assert issubclass(peer_cls, TestPeer), "The provided class type is not for testing (i.e. a subclass of " \
                                               "TestPeer"
        assert port is None or isinstance(port, int), "The port must be an int or None"
        # Check to see if a peer was provided; if not, generate it
        if port is None:
            port = self.other_peer_port
            RESTTestBase.other_peer_port += 1

        # Create the new peer arguments
        temp_args = [port] + list(args)

        # Create a directory if this peer requires it.
        if not kwargs.get('memory_dbs', True):
            working_dir_path = self.create_dir()
            self.working_dirs.add(working_dir_path)
            os.chdir(working_dir_path)

        # Create the new peer, and add it to the list of peers for this test
        new_peer = peer_cls(*temp_args, **kwargs)
        self.peer_list.append(new_peer)

        # Move back to the test level, if a new directory was created
        if not kwargs.get('memory_dbs', True):
            os.chdir(os.path.dirname(__file__))

        return new_peer, len(self.peer_list) - 1

    def create_dir(self):
        """
        Create a random working directory

        :return: the path to the directory
        """
        os.chdir(os.path.dirname(__file__))
        random_string = '_temp_' + ''.join(choice(ascii_uppercase + digits) for _ in range(10))
        d = os.path.abspath(self.__class__.__name__ + random_string)
        os.makedirs(d)
        return d

    @inlineCallbacks
    def deliver_messages(self, timeout=.1):
        """
        Allow peers to communicate.

        The strategy is as follows:
         1. Measure the amount of working threads in the threadpool
         2. After 10 milliseconds, check if we are down to 0 twice in a row
         3. If not, go back to handling calls (step 2) or return, if the timeout has been reached

        :param timeout: the maximum time to wait for messages to be delivered
        """
        rtime = 0
        probable_exit = False
        while (rtime < timeout):
            yield self.sleep(.01)
            rtime += .01
            if len(reactor.getThreadPool().working) == 0:
                if probable_exit:
                    break
                probable_exit = True
            else:
                probable_exit = False

    @inlineCallbacks
    def sleep(self, time=.05):
        yield deferLater(reactor, time, lambda: None)

    @inlineCallbacks
    def introduce_nodes(self, overlay_class):
        # for node in self.peer_list:
        #     node.add_and_verify_peers([other for other in self.peer_list if other != node])

        for node in self.peer_list:
            for other in self.peer_list:
                other.get_overlay_by_class(overlay_class).walk_to(node.get_address())
        yield self.deliver_messages()

    def gracefully_terminate_peers(self):
        """
        Gracefully terminate the peers passed as parameter

        :return: None
        """
        for peer in self.peer_list:
            if isinstance(peer, Thread):
                peer.join()
            peer.close()
