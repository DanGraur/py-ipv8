import json
import time
import unittest
from urllib import quote
from base64 import b64encode

from twisted.internet.defer import returnValue, inlineCallbacks
from twisted.web.error import SchemeNotSupported

from ipv8.test.REST.rtest.peer_communication import GetStyleRequests, PostStyleRequests
from ipv8.test.REST.rtest.peer_interactive_behavior import AndroidTestPeer
from ipv8.test.REST.rtest.rest_peer_communication import HTTPGetRequester, HTTPPostRequester
from ipv8.test.REST.rtest.test_rest_api_peer import TestPeer
from ipv8.test.util import twisted_wrapper


class SingleServerSetup(unittest.TestCase):
    """AndroidTestPeer
    Test class which defines an environment with one well-known peer. This should be extended by other subclasses,
    which implement specific test cases.
    """

    def __init__(self, *args, **kwargs):
        super(SingleServerSetup, self).__init__(*args, **kwargs)

        # Call the method which sets up the environment
        self.initialize()

    def initialize(self, **kwargs):
        """
        An initializer method for the Single Server test environment

        :param kwargs: a dictionary containing additional configuration parameters:
        {
            'port': the master peer's port. Defaults to 8086
            '8086': the master peer's path to the working directory. Defaults to 'test_env'
            'interface': IP or alias of the peer. Defaults to '127.0.0.1'
            'configuration': IPv8 configuration object. Defaults to None
            'get_style_requests': GET style request generator. Defaults to None
            'post_style_requests': POST style request generator. Defaults to None
        }
        """

        port = kwargs.get('port', 8086)
        path = kwargs.get('path', 'test_env')
        interface = kwargs.get('interface', '127.0.0.1')
        configuration = kwargs.get('configuration', None)
        get_style_requests = kwargs.get('get_style_requests', None)
        post_style_requests = kwargs.get('post_style_requests', None)

        # Create a so called master (well-known) peer, which should be the peer to which the requests are directed
        self._master_peer = TestPeer(path, port, interface, configuration)

        # Check to see if the user has provided request generators
        if get_style_requests:
            assert isinstance(get_style_requests, GetStyleRequests), "The get_style_requests parameter must be a " \
                                                                     "subclass of GetStyleRequests"
            self._get_style_requests = get_style_requests
        else:
            # If no get style request provided, default to the HTTP implementation
            self._get_style_requests = HTTPGetRequester()

        if post_style_requests:
            assert isinstance(post_style_requests, PostStyleRequests), "The post_style_requests parameter must be a " \
                                                                       "subclass of PostStyleRequests"
            self._post_style_requests = post_style_requests
        else:
            # If no post style request provided, default to the HTTP implementation
            self._post_style_requests = HTTPPostRequester()

    def setUp(self):
        # Call super method
        pass

    def tearDown(self):
        # Call super method
        super(SingleServerSetup, self).tearDown()

        # Stop the master peer
        self._master_peer.stop()


class RequestTest(SingleServerSetup):

    @inlineCallbacks
    def wait_for_peers(self, dict_param):
        """
        Wait until this peer receives a non-empty list of fellow peers in the network

        :param dict_param: the required parameters by the GET request generator for the peers request type
        :return: a list of currently known peers in the network
        """

        peer_list = yield self._get_style_requests.make_peers(dict_param)

        # Keep iterating until peer_list is non-empty
        while peer_list == "[]":
            # Wait for 4 seconds before trying again
            time.sleep(4)

            # Forward and wait for the response
            peer_list = yield self._get_style_requests.make_peers(dict_param)

        # Return the peer list
        returnValue(peer_list)

    @inlineCallbacks
    def wait_for_attestation_request(self, dict_param):
        """
        Wait until this peer receives a non-empty list of outstanding attestation requests

        :param dict_param: the required parameters by the GET request generator for the outstanding request type
        :return: a list of outstanding attestation requests
        """
        outstanding_requests = yield self._get_style_requests.make_outstanding(dict_param)

        # Keep iterating until peer_list is non-empty
        while outstanding_requests == "[]":
            # Wait for 4 seconds before trying again
            time.sleep(4)

            # Forward and wait for the response
            outstanding_requests = yield self._get_style_requests.make_outstanding(dict_param)

        # Return the peer list
        returnValue(outstanding_requests)

    @twisted_wrapper
    def test_get_peers_request(self):
        """
        Test the GET: peers request type
        :return: None
        """
        param_dict = {
            'port': 8086,
            'interface': '127.0.0.1',
            'endpoint': 'attestation'
        }

        result = yield self._get_style_requests.make_peers(param_dict)
        print "The response body:", result

    @twisted_wrapper
    def test_get_outstanding_requests(self):
        """
        Test the GET: outstanding request type
        :return: None
        """
        param_dict = {
            'port': 8086,
            'interface': '127.0.0.1',
            'endpoint': 'attestation'
        }

        result = yield self._get_style_requests.make_outstanding(param_dict)
        print "The response body:", result

    @twisted_wrapper
    def test_get_verification_output(self):
        """
        Test the GET: verification output request type
        :return: None
        """
        param_dict = {
            'port': 8086,
            'interface': '127.0.0.1',
            'endpoint': 'attestation'
        }

        result = yield self._get_style_requests.make_verification_output(param_dict)
        print "The response body:", result

    @twisted_wrapper
    def test_get_attributes(self):
        """
        Test the GET: attributes request type
        :return: None
        """
        param_dict = {
            'port': 8086,
            'interface': '127.0.0.1',
            'endpoint': 'attestation'
        }

        result = yield self._get_style_requests.make_attributes(param_dict)
        print "The response body:", result

    @twisted_wrapper
    def test_get_drop_identity(self):
        """
        Test the GET: drop identity request type
        :return: None
        """
        param_dict = {
            'port': 8086,
            'interface': '127.0.0.1',
            'endpoint': 'attestation'
        }

        result = yield self._get_style_requests.make_drop_identity(param_dict)
        print "The response body:", result

    @twisted_wrapper
    def test_post_attestation_request(self):
        """
        Test the POST: request request type
        :return: None
        """
        param_dict = {
            'port': 8086,
            'interface': '127.0.0.1',
            'endpoint': 'attestation',
            'attribute_name': 'QR',
            'mid': '4AFiooDqnS0xnCOHq8npGmwUXXY='
        }

        result = yield self._post_style_requests.make_attestation_request(param_dict)
        print "The response body:", result

    @twisted_wrapper(300)
    def test_post_attest(self):

        param_dict = {
            'port': 8086,
            'interface': '127.0.0.1',
            'endpoint': 'attestation'
        }

        client_peer = AndroidTestPeer(param_dict, 'client_peer', 9876)
        client_peer.start()

        from json import loads

        for peer in self._master_peer.get_keys().iteritems():
            print peer[0], b64encode(peer[1].mid)

        try:
            value = yield self.wait_for_peers(param_dict)
            print "Known peers:", value
            done = False
            while not done:
                value = yield self.wait_for_attestation_request(param_dict)
                value = loads(value)
                print "Pending attestation request for attester:", value
                # raw_input('PRESS ANY KEY TO CONTINUE')
                for (identifier, attribute) in value:
                    param_dict['mid'] = str(identifier).replace("+", "%2B")
                    param_dict['attribute_name'] = str(attribute)
                    param_dict['attribute_value'] = quote(b64encode('binarydata')).replace("+", "%2B")

                    yield self._post_style_requests.make_attest(param_dict)
                    done = True
        except SchemeNotSupported:
            import traceback
            traceback.print_exc()

        client_peer.join()

    @twisted_wrapper
    def test_post_verify(self):
        """
        Test the POST: verify request type
        :return: None
        """

        values = ""

        for i in range(10):
            values = values + ',' + b64encode(str(i))

        values = values[1:]

        param_dict = {
            'port': 8086,
            'interface': '127.0.0.1',
            'endpoint': 'attestation',
            'mid': '4AFiooDqnS0xnCOHq8npGmwUXXY=',
            'attribute_hash': quote(b64encode('binarydata')).replace("+", "%2B"),
            'attribute_values': values
        }

        result = yield self._post_style_requests.make_verify(param_dict)
        print "The response body:", result
