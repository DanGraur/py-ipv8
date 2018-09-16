import os
import unittest
from base64 import b64encode
from json import dumps
from random import choice
from string import ascii_letters
from shutil import rmtree
from threading import Thread

from twisted.internet import reactor
from twisted.internet.defer import returnValue, inlineCallbacks
from twisted.internet.task import deferLater

from .peer_communication import GetStyleRequests, PostStyleRequests
from .peer_interactive_behavior import AndroidTestPeer
from .rest_peer_communication import HTTPGetRequester, HTTPPostRequester, string_to_url
from .test_rest_api_peer import TestPeer
from ...util import twisted_wrapper
from ....attestation.trustchain.block import TrustChainBlock

TEST_FOLDER_PREFIX = "test_temp"


class TestRESTAPI(unittest.TestCase):
    """
    Class for testing the REST API of the IPv8 object
    """

    other_peer_port = 7868

    def __init__(self, method_name='runTest'):
        super(TestRESTAPI, self).__init__(method_name)
        self.peer_list = []
        self.default_test_folder = '_trial_temp'
        self._get_style_requests = None
        self._post_style_requests = None

    def initialize(self, get_style_requests=None, post_style_requests=None):
        """
        An initializer method for the Single Server test environment

        :param get_style_requests: GET style request generator. Defaults to None.
        :param post_style_requests: POST style request generator. Defaults to None.
        :return:
        """
        assert get_style_requests is None or isinstance(get_style_requests, GetStyleRequests), \
            "The get_style_requests parameter must be a subclass of GetStyleRequests"
        assert post_style_requests is None or isinstance(post_style_requests, PostStyleRequests), \
            "The post_style_requests parameter must be a subclass of PostStyleRequests"

        # Check to see if the user has provided request generators
        self._get_style_requests = get_style_requests if get_style_requests is not None else HTTPGetRequester()
        self._post_style_requests = post_style_requests if post_style_requests is not None else HTTPPostRequester()

    def setUp(self):
        super(TestRESTAPI, self).setUp()
        self.initialize()

        self.peer_list = []
        self.create_new_peer(TestPeer, 'temp_initial_peer', None)

    def tearDown(self):
        super(TestRESTAPI, self).tearDown()

        self.gracefully_terminate_peers()

        # We ignore errors so there's no need to check if these dirs are there before removing the subtree
        rmtree(self.default_test_folder, ignore_errors=True)
        rmtree(TEST_FOLDER_PREFIX)

    def create_new_peer(self, peer_cls, path, port, *args, **kwargs):
        """
        Create and return a new peer for testing.

        :param peer_cls: specifies the test class of the new peer
        :param path: the path / working directory of the peer
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
        # Add a prefix to the path of the peer

        path = os.path.join(TEST_FOLDER_PREFIX, path)
        path += ''.join(choice(ascii_letters) for _ in range(10))

        # Check to see if a peer was provided; if not, generate it
        if port is None:
            port = self.other_peer_port
            TestRESTAPI.other_peer_port += 1

        # Create the new peer arguments
        temp_args = [path, port] + list(args)

        # Create the new peer, and add it to the list of peers for this test
        new_peer = peer_cls(*temp_args, **kwargs)
        self.peer_list.append(new_peer)

        return new_peer, len(self.peer_list) - 1

    @inlineCallbacks
    def wait_for_peers(self, dict_param, excluded_peer_mids=None):
        """
        Wait until this peer receives a non-empty list of fellow peers in the network

        :param dict_param: the required parameters by the GET request generator for the peers request type
        :param excluded_peer_mids: A list of peer mids which should not be taken into consideration peers
        :return: a list of currently known peers in the network
        """
        assert isinstance(excluded_peer_mids, (list, set)) or not excluded_peer_mids, "excluded_peer_mids " \
                                                                                      "must be a list, set or None"

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
    def wait_for_outstanding_requests(self, dict_param):
        """
        Wait until this peer receives a non-empty list of outstanding attestation requests

        :param dict_param: the required parameters by the GET request generator for the outstanding request type
        :return: a list of outstanding attestation requests
        """
        outstanding_requests = yield self._get_style_requests.make_outstanding(dict_param)

        # Keep iterating until peer_list is non-empty
        while not outstanding_requests:
            yield deferLater(reactor, 0.1, lambda: None)

            # Forward and wait for the response
            outstanding_requests = yield self._get_style_requests.make_outstanding(dict_param)

        # Return the peer list
        returnValue(outstanding_requests)

    @inlineCallbacks
    def attest_all_outstanding_requests(self, param_dict):
        """
        Forward an attestation for each of the outstanding attestation requests

        :param param_dict: the parameters required to contact a well-known peer for the POST and GET requests
        :return: a list of the outstanding requests and their (empty if successful) request responses
        """
        assert 'attribute_name' in param_dict, "No attribute name was specified"
        assert 'attribute_value' in param_dict, "No attribute value was specified"

        outstanding_requests = yield self.wait_for_outstanding_requests(param_dict)
        self.assertFalse(outstanding_requests == [], "Something went wrong, no request was received.")

        # Collect the responses of the attestations; if functioning properly, this should be a list of empty strings
        responses = []

        for outstanding_request in outstanding_requests:
            # The attestation value is already computed, so don't bother recomputing it here
            param_dict['mid'] = string_to_url(outstanding_request[0])
            response = yield self._post_style_requests.make_attest(param_dict)
            responses.append(response)

        returnValue((outstanding_requests, responses))

    @inlineCallbacks
    def verify_all_attestations(self, peer_mids, param_dict):
        """
        Forward an attestation verification for a set of attestations

        :param peer_mids: the set of peer mids to which a verification request will be sent
        :param param_dict: the parameters required to contact a well-known peer for the POST: verify request
        :return: the verification responses, as returned by the well-known peer. Ideally these should be all empty
        """
        assert peer_mids, "Attestation list is empty"
        assert 'attribute_hash' in param_dict, "No attestation hash was specified"
        assert 'attribute_values' in param_dict, "No attestation values were specified"

        verification_responses = []

        for mid in peer_mids:
            param_dict['mid'] = string_to_url(mid)
            intermediary_response = yield self._post_style_requests.make_verify(param_dict)
            verification_responses.append(intermediary_response)

        returnValue(verification_responses)

    def gracefully_terminate_peers(self):
        """
        Gracefully terminate the peers passed as parameter

        :return: None
        """
        for peer in self.peer_list:
            if isinstance(peer, Thread):
                peer.join()
            peer.close()

    @twisted_wrapper(30)
    def test_get_peers_request(self):
        """
        Test the (GET: peers request) type
        :return: None
        """
        param_dict = {
            'port': self.peer_list[0].port,
            'interface': self.peer_list[0].interface,
            'endpoint': 'attestation'
        }

        # Create a dummy peer which will be used towards peer discovery; there is no need to start() it
        self.create_new_peer(TestPeer, 'temp_local_peer', None)
        other_peer_mids = [b64encode(x.mid) for x in self.peer_list[1].get_keys().values()]

        # Add the peers
        self.peer_list[0].add_and_verify_peers([self.peer_list[1]])

        result = yield self.wait_for_peers(param_dict)

        self.assertTrue(any(x in other_peer_mids for x in result), "Could not find the second peer.")

    @twisted_wrapper(30)
    def test_get_outstanding_requests(self):
        """
        Test the (GET: outstanding) request type
        :return: None
        """
        param_dict = {
            'port': self.peer_list[0].port,
            'interface': self.peer_list[0].interface,
            'endpoint': 'attestation',
            'attribute_name': 'QR'
        }

        self.create_new_peer(AndroidTestPeer, 'temp_local_peer', None, param_dict.copy(),
                             other_verified_peers=[self.peer_list[0]])
        self.peer_list[1].start()

        result = yield self.wait_for_outstanding_requests(param_dict)

        self.assertTrue(any((x[0] == y and x[1] == param_dict['attribute_name'] for x in result)
                            for y in self.peer_list[1].get_mids()),
                        "Could not find the outstanding request forwarded by the second peer")

    @twisted_wrapper(30)
    def test_get_verification_output(self):
        """
        Test the (GET: verification output) request type
        :return: None
        """
        param_dict = {
            'port': self.peer_list[0].port,
            'interface': self.peer_list[0].interface,
            'endpoint': 'attestation',
            'attribute_name': 'QR',
            'attribute_value': string_to_url(b64encode('binarydata'), True),
            'attribute_values': 'YXNk,YXNkMg==',
            'metadata': b64encode(dumps({'psn': '1234567890'}))
        }

        # Forward the attestations to the well-known peer
        self.create_new_peer(AndroidTestPeer, 'temp_local_peer', None, param_dict.copy(),
                             other_verified_peers=[self.peer_list[0]])
        self.peer_list[1].start()

        yield self.attest_all_outstanding_requests(param_dict.copy())

        # Get the hash of the attestation to be validated (the one which was just attested)
        attributes = yield self._get_style_requests.make_attributes(param_dict)
        param_dict['attribute_hash'] = string_to_url(attributes[0][1])

        # Forward the actual verification
        verification_responses = yield self.verify_all_attestations(self.peer_list[1].get_mids(), param_dict.copy())
        self.assertTrue(all(x == "" for x in verification_responses), "At least one of the verification "
                                                                      "responses was non-empty.")

        # Unlock the verification
        param_dict['port'] = self.peer_list[1].port

        outstanding_verifications = yield self._get_style_requests.make_outstanding_verify(param_dict)
        self.assertIsNotNone(outstanding_verifications, "Could not retrieve any outstanding verifications")

        param_dict['mid'] = string_to_url(outstanding_verifications[0][0])

        yield self._post_style_requests.make_allow_verify(param_dict)
        yield deferLater(reactor, 1, lambda: None)

        param_dict['port'] = self.peer_list[0].port

        # Get the output
        verification_output = yield self._get_style_requests.make_verification_output(param_dict)

        self.assertTrue([["YXNk", 0.0], ["YXNkMg==", 0.0]] in verification_output.values(),
                        "Something went wrong with the verification. Unexpected output values.")

    @twisted_wrapper(30)
    def test_get_outstanding_verify(self):
        """
        Test the (GET: outstanding verify) request type
        :return: None
        """
        param_dict = {
            'port': self.peer_list[0].port,
            'interface': self.peer_list[0].interface,
            'endpoint': 'attestation',
            'attribute_name': 'QR',
            'attribute_value': string_to_url(b64encode('binarydata'), True),
            'attribute_values': 'YXNk,YXNkMg==',
            'metadata': b64encode(dumps({'psn': '1234567890'}))
        }

        # Forward the attestations to the well-known peer
        self.create_new_peer(AndroidTestPeer, 'temp_local_peer', None, param_dict.copy(),
                             other_verified_peers=[self.peer_list[0]])

        self.peer_list[1].start()

        yield self.attest_all_outstanding_requests(param_dict.copy())

        # Get the hash of the attestation to be validated (the one which was just attested)
        attributes = yield self._get_style_requests.make_attributes(param_dict)
        param_dict['attribute_hash'] = string_to_url(attributes[0][1])

        # Forward the actual verification
        verification_responses = yield self.verify_all_attestations(self.peer_list[1].get_mids(), param_dict.copy())
        self.assertTrue(all(x == "" for x in verification_responses), "At least one of the verification "
                                                                      "responses was non-empty.")

        param_dict['port'] = self.peer_list[1].port
        result = yield self._get_style_requests.make_outstanding_verify(param_dict)

        # Retrieve only the mids
        result = [x[0] for x in result]

        self.assertTrue(any(x in result for x in self.peer_list[0].get_mids(False)), "Something went wrong. Could not "
                                                                                     "find a master peer mid in the "
                                                                                     "outstanding verification "
                                                                                     "requests.")

    @twisted_wrapper(30)
    def test_get_attributes(self):
        """
        Test the (GET: attributes) request type
        :return: None
        """
        param_dict = {
            'port': self.peer_list[0].port,
            'interface': self.peer_list[0].interface,
            'endpoint': 'attestation'
        }

        block = TrustChainBlock()
        block.public_key = self.peer_list[0].get_overlay_by_name('IdentityCommunity').my_peer.public_key.key_to_bin()
        block.transaction = {'name': 123, 'hash': '123', 'metadata': b64encode(dumps({'psn': '1234567890'}))}

        self.peer_list[0].get_overlay_by_name('IdentityCommunity').persistence.add_block(block)

        result = yield self._get_style_requests.make_attributes(param_dict)

        self.assertEqual(result, [[123, "MTIz", "eyJwc24iOiAiMTIzNDU2Nzg5MCJ9", "awzBTMhmU9B4lQuMxT1DS03TPfU="]],
                         "The response was not as expected. This would suggest that something went wrong "
                         "with the attributes request. The error: '%s'" % result)

    @twisted_wrapper(30)
    def test_get_attributes_alternative(self):
        """
        Test the (GET: attributes) request type
        :return: None
        """
        param_dict = {
            'port': self.peer_list[0].port,
            'interface': self.peer_list[0].interface,
            'endpoint': 'attestation',
            'attribute_name': 'QR',
            'attribute_value': string_to_url(b64encode('binarydata'), True),
            'attribute_values': 'YXNk,YXNkMg==',
            'metadata': b64encode(dumps({'psn': '1234567890'}))
        }

        # Forward the attestations to the well-known peer
        self.create_new_peer(AndroidTestPeer, 'temp_local_peer', None, param_dict.copy(),
                             other_verified_peers=[self.peer_list[0]])
        self.peer_list[1].start()

        yield self.attest_all_outstanding_requests(param_dict.copy())

        # Get the hash of the attestation to be validated (the one which was just attested)
        attributes = yield self._get_style_requests.make_attributes(param_dict)

        self.assertTrue(attributes[0][0] == param_dict['attribute_name'] and attributes[0][1] != "",
                        "The response was not as expected. This would suggest that something went wrong with "
                        "the attributes request.")

    @twisted_wrapper(30)
    def test_get_drop_identity(self):
        """
        Test the (GET: drop identity) request type
        :return: None
        """
        param_dict = {
            'port': self.peer_list[0].port,
            'interface': self.peer_list[0].interface,
            'endpoint': 'attestation',
            'attribute_name': 'QR',
            'attribute_value': string_to_url(b64encode('binarydata'), True),
            'attribute_values': 'YXNk,YXNkMg==',
            'metadata': b64encode(dumps({'psn': '1234567890'}))
        }

        # Send a random attestation request to the well-known peer
        self.create_new_peer(AndroidTestPeer, 'temp_local_peer', None, param_dict.copy(),
                             other_verified_peers=[self.peer_list[0]])
        self.peer_list[1].start()

        outstanding_requests = yield self.wait_for_outstanding_requests(param_dict)

        self.assertFalse(outstanding_requests == [], "The attestation requests were not received.")

        # Ensure that no block/attestation exists
        attributes = yield self._get_style_requests.make_attributes(param_dict)
        self.assertEqual(attributes, [], "Something's wrong, there shouldn't be any blocks.")

        # Attest the outstanding request. This should mean that the attribute DB is non-empty in the well-known peer
        yield self.attest_all_outstanding_requests(param_dict)

        # Ensure that the attestation has been completed
        attributes = yield self._get_style_requests.make_attributes(param_dict)
        self.assertNotEqual(attributes, [], "Something's wrong, the attribute list should be non-empty.")

        # Drop the identity
        result = yield self._get_style_requests.make_drop_identity(param_dict)
        self.assertEqual(result, "", "The identity could not be dropped. Received non-empty response.")

        # Make sure the identity was successfully dropped
        result = yield self._get_style_requests.make_attributes(param_dict)
        self.assertEqual(result, [], 'The identity could not be dropped. Block DB still populated.')

        result = yield self._get_style_requests.make_outstanding(param_dict)
        self.assertEqual(result, [], 'The identity could not be dropped. Outstanding requests still remaining.')

    @twisted_wrapper(30)
    def test_post_attestation_request(self):
        """
        Test the (POST: request) request type
        :return: None
        """
        param_dict = {
            'port': self.peer_list[0].port,
            'interface': self.peer_list[0].interface,
            'endpoint': 'attestation',
            'attribute_name': 'QR',
            'metadata': b64encode(dumps({'psn': '1234567890'}))
        }

        # This should return an empty response
        outstanding_requests = yield self._get_style_requests.make_outstanding(param_dict)

        self.assertEqual(outstanding_requests, [], "Something went wrong, there should be no outstanding requests.")

        self.create_new_peer(AndroidTestPeer, 'temp_local_peer', None, param_dict.copy(),
                             other_verified_peers=[self.peer_list[0]])
        self.peer_list[1].start()

        # This should return a non-empty response
        outstanding_requests = yield self.wait_for_outstanding_requests(param_dict)
        self.assertFalse(outstanding_requests == [], "Something went wrong, no request was received.")

    @twisted_wrapper(30)
    def test_post_attest(self):
        """
        Test the (POST: attest) request type
        :return: None
        """
        param_dict = {
            'port': self.peer_list[0].port,
            'interface': self.peer_list[0].interface,
            'endpoint': 'attestation',
            'attribute_name': 'QR',
            'attribute_value': string_to_url(b64encode('binarydata'), True),
            'metadata': b64encode(dumps({'psn': '1234567890'}))
        }

        self.create_new_peer(AndroidTestPeer, 'temp_local_peer', None, param_dict.copy(),
                             other_verified_peers=[self.peer_list[0]])
        self.peer_list[1].start()

        param_dict['port'] = self.peer_list[1].port
        attributes = yield self._get_style_requests.make_attributes(param_dict)
        self.assertTrue(len(attributes) == 0, "There mustn't already be any attestations in the other peer.")

        param_dict['port'] = self.peer_list[0].port
        responses = yield self.attest_all_outstanding_requests(param_dict.copy())
        self.assertTrue(all(x == "" for x in responses[1]), "Something went wrong, not all responses were empty.")

        param_dict['port'] = self.peer_list[1].port
        attributes = yield self._get_style_requests.make_attributes(param_dict)
        self.assertTrue(len(attributes) == 1, "There should only be one attestation in the DB.")
        self.assertTrue(attributes[0][0] == param_dict['attribute_name'], "Expected attestation for %s, got it for "
                                                                          "%s" % (param_dict['attribute_name'],
                                                                                  attributes[0][0]))

    @twisted_wrapper(30)
    def test_post_verify(self):
        """
        Test the (POST: verify) request type
        :return: None
        """
        param_dict = {
            'port': self.peer_list[0].port,
            'interface': self.peer_list[0].interface,
            'endpoint': 'attestation',
            'attribute_name': 'QR',
            'attribute_value': string_to_url(b64encode('binarydata'), True),
            'attribute_values': 'YXNk,YXNkMg==',
            'metadata': b64encode(dumps({'psn': '1234567890'}))
        }

        # Forward the attestations to the well-known peer
        self.create_new_peer(AndroidTestPeer, 'temp_local_peer', None, param_dict.copy(),
                             other_verified_peers=[self.peer_list[0]])
        self.peer_list[1].start()

        yield self.attest_all_outstanding_requests(param_dict.copy())

        # Get the mids of the other peer
        other_peer_mids = [string_to_url(b64encode(x.mid)) for x in self.peer_list[1].get_keys().values()]

        # Get the hash of the attestation to be validated (the one which was just attested)
        attributes = yield self._get_style_requests.make_attributes(param_dict)
        param_dict['attribute_hash'] = string_to_url(attributes[0][1])

        # Forward the actual verification
        verification_responses = yield self.verify_all_attestations(other_peer_mids, param_dict.copy())

        self.assertTrue(all(x == "" for x in verification_responses), "At least one of the verification "
                                                                      "responses was non-empty.")

    @twisted_wrapper(30)
    def test_post_allow_verify(self):
        """
        Test the (POST: allow verify) request type
        :return: None
        """
        param_dict = {
            'port': self.peer_list[0].port,
            'interface': self.peer_list[0].interface,
            'endpoint': 'attestation',
            'attribute_name': 'QR',
            'attribute_value': string_to_url(b64encode('binarydata'), True),
            'attribute_values': 'YXNk,YXNkMg==',
            'metadata': b64encode(dumps({'psn': '1234567890'}))
        }

        # Forward the attestations to the well-known peer
        self.create_new_peer(AndroidTestPeer, 'temp_local_peer', None, param_dict.copy(),
                             other_verified_peers=[self.peer_list[0]])
        self.peer_list[1].start()

        yield self.attest_all_outstanding_requests(param_dict.copy())

        # Get the hash of the attestation to be validated (the one which was just attested)
        attributes = yield self._get_style_requests.make_attributes(param_dict)
        param_dict['attribute_hash'] = string_to_url(attributes[0][1])

        # Forward the actual verification
        verification_responses = yield self.verify_all_attestations(self.peer_list[1].get_mids(), param_dict.copy())
        self.assertTrue(all(x == "" for x in verification_responses), "At least one of the verification "
                                                                      "responses was non-empty.")

        # Unlock the verification
        param_dict['port'] = self.peer_list[1].port

        outstanding_verifications = yield self._get_style_requests.make_outstanding_verify(param_dict)
        self.assertIsNotNone(outstanding_verifications, "Could not retrieve any outstanding verifications")

        param_dict['mid'] = string_to_url(outstanding_verifications[0][0])

        response = yield self._post_style_requests.make_allow_verify(param_dict)

        self.assertEqual("", response, "The attestation could not be unlocked.")
