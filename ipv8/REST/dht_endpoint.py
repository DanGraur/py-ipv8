from __future__ import absolute_import

from base64 import b64encode, b64decode
from binascii import hexlify, unhexlify
from hashlib import sha1
import json
import struct

from twisted.internet.defer import inlineCallbacks, returnValue
from twisted.web import http, resource
from twisted.web.server import NOT_DONE_YET

from ..dht.community import DHTCommunity, MAX_ENTRY_SIZE
from ..attestation.trustchain.community import TrustChainCommunity
from ..dht.discovery import DHTDiscoveryCommunity


class DHTEndpoint(resource.Resource):
    """
    This endpoint is responsible for handling requests for DHT data.
    """

    def __init__(self, session):
        resource.Resource.__init__(self)

        dht_overlays = [overlay for overlay in session.overlays if isinstance(overlay, DHTCommunity)]
        tc_overlays = [overlay for overlay in session.overlays if isinstance(overlay, TrustChainCommunity)]
        if dht_overlays:
            self.putChild("statistics", DHTStatisticsEndpoint(dht_overlays[0]))
            self.putChild("values", DHTValuesEndpoint(dht_overlays[0]))
            self.putChild("peers", DHTPeersEndpoint(dht_overlays[0]))
            self.putChild("block", DHTBlockEndpoint(dht_overlays[0], tc_overlays[0]))


class DHTBlockEndpoint(resource.Resource):
    """
    This endpoint is responsible for returning the latest Trustchain block of a peer. Additionally, it ensures
    this peer's latest TC block is available
    """

    KEY_SUFFIX = b'_BLOCK'

    def __init__(self, dht, trustchain):
        resource.Resource.__init__(self)
        self.dht = dht
        self.trustchain = trustchain
        self.block_version = 0

        self._hashed_dht_key = sha1(self.trustchain.my_peer.mid + self.KEY_SUFFIX).digest()

        trustchain.set_new_block_cb(self.publish_latest_block)

    @inlineCallbacks
    def publish_latest_block(self):
        """
        Publish the latest block of this node's Trustchain to the DHT

        :return:
        """
        # latest_block = self.trustchain.persistence.get_latest(self.trustchain.my_peer.key.pub().key_to_bin())
        latest_block = self.trustchain.persistence.get_latest(self.trustchain.my_peer.public_key.key_to_bin())

        if latest_block:
            latest_block = latest_block.pack()
            version = struct.pack("H", self.block_version)
            self.block_version += 1

            for i in range(0, len(latest_block), MAX_ENTRY_SIZE - 3):
                blob_chunk = version + latest_block[i:i + MAX_ENTRY_SIZE - 3]
                yield self.dht.store_value(self._hashed_dht_key, blob_chunk)

    def render_GET(self, request):
        """
        Return the latest TC block of a peer, as identified in the request

        :param request: the request for retrieving the latest TC block of a peer. It must contain the peer's
        public key of the peer
        :return: the latest block of the peer, if found
        """
        if not self.dht:
            request.setResponseCode(http.NOT_FOUND)
            return json.dumps({"error": "DHT community not found"}).encode('utf-8')

        if not request.args or 'public_key' not in request.args:
            request.setResponseCode(http.BAD_REQUEST)
            return json.dumps({"error": "Must specify the peer's public key"}).encode('utf-8')

        hash_key = sha1(b64decode(request.args[b'public_key'][0]) + self.KEY_SUFFIX).digest()
        block_chunks = self.dht.storage.get(hash_key)

        if not block_chunks:
            request.setResponseCode(http.NOT_FOUND)
            return json.dumps({"error": "Could not find a block for the specified key."}).encode('utf-8')

        new_blocks = {}
        max_version = 0

        for entry in block_chunks:
            this_version = struct.unpack("I", entry[1:3] + '\x00\x00')[0]
            max_version = max_version if max_version > this_version else this_version

            if this_version in new_blocks:
                new_blocks[this_version] = entry[3:] + new_blocks[this_version]
            else:
                new_blocks[this_version] = entry[3:]

        return json.dumps({b"block": b64encode(new_blocks[max_version])}).encode('utf-8')


class DHTStatisticsEndpoint(resource.Resource):
    """
    This endpoint is responsible for returning statistics about the DHT.
    """

    def __init__(self, dht):
        resource.Resource.__init__(self)
        self.dht = dht

    def render_GET(self, request):
        if not self.dht:
            request.setResponseCode(http.NOT_FOUND)
            return json.dumps({"error": "DHT community not found"})

        buckets = self.dht.routing_table.trie.values()
        stats = {"node_id": hexlify(self.dht.my_node_id),
                 "peer_id": hexlify(self.dht.my_peer.mid),
                 "routing_table_size": sum([len(bucket.nodes) for bucket in buckets]),
                 "routing_table_buckets": len(buckets),
                 "num_keys_in_store": len(self.dht.storage.items),
                 "num_tokens": len(self.dht.tokens)}

        if isinstance(self.dht, DHTDiscoveryCommunity):
            stats.update({
                "num_peers_in_store": {hexlify(key): len(peers) for key, peers in self.dht.store.items()},
                "num_store_for_me": {hexlify(key): len(peers) for key, peers in self.dht.store_for_me.items()}
            })

        return json.dumps({"statistics": stats})


class DHTPeersEndpoint(resource.Resource):
    """
    This endpoint is responsible for handling requests for DHT peers.
    """

    def __init__(self, dht):
        resource.Resource.__init__(self)
        self.dht = dht

    def getChild(self, path, request):
        return SpecificDHTPeerEndpoint(self.dht, path)


class SpecificDHTPeerEndpoint(resource.Resource):
    """
    This class handles requests for a specific DHT peer.
    """

    def __init__(self, dht, key):
        resource.Resource.__init__(self)
        self.mid = bytes(unhexlify(key))
        self.dht = dht

    def render_GET(self, request):
        if not self.dht:
            request.setResponseCode(http.NOT_FOUND)
            return json.dumps({"error": "DHT community not found"})

        def on_success(nodes):
            node_dicts = []
            for node in nodes:
                node_dicts.append({'public_key': b64encode(node.public_key.key_to_bin()),
                                   'address': node.address})
            request.write(json.dumps({"peers": node_dicts}))
            request.finish()

        def on_failure(failure):
            request.setResponseCode(http.INTERNAL_SERVER_ERROR)
            request.write(json.dumps({
                u"error": {
                    u"handled": True,
                    u"code": failure.value.__class__.__name__,
                    u"message": failure.value.message
                }
            }))

        deferred = self.dht.connect_peer(self.mid)
        deferred.addCallback(on_success)
        deferred.addErrback(on_failure)

        return NOT_DONE_YET


class DHTValuesEndpoint(resource.Resource):
    """
    This endpoint is responsible for handling requests for DHT values.
    """

    def __init__(self, dht):
        resource.Resource.__init__(self)
        self.dht = dht

    def getChild(self, path, request):
        return SpecificDHTValueEndpoint(self.dht, path)


class SpecificDHTValueEndpoint(resource.Resource):
    """
    This class handles requests for a specific DHT value.
    """

    def __init__(self, dht, key):
        resource.Resource.__init__(self)
        self.key = bytes(unhexlify(key))
        self.dht = dht

    def render_GET(self, request):
        if not self.dht:
            request.setResponseCode(http.NOT_FOUND)
            return json.dumps({"error": "DHT community not found"})

        def on_success(values):
            dicts = []
            for value in values:
                data, public_key = value
                dicts.append({'public_key': b64encode(public_key) if public_key else None,
                              'value': hexlify(data)})
            request.write(json.dumps({"values": dicts}))
            request.finish()

        def on_failure(failure):
            request.setResponseCode(http.INTERNAL_SERVER_ERROR)
            request.write(json.dumps({
                u"error": {
                    u"handled": True,
                    u"code": failure.value.__class__.__name__,
                    u"message": failure.value.message
                }
            }))

        deferred = self.dht.find_values(self.key)
        deferred.addCallback(on_success)
        deferred.addErrback(on_failure)

        return NOT_DONE_YET

    def render_PUT(self, request):
        if not self.dht:
            request.setResponseCode(http.NOT_FOUND)
            return json.dumps({"error": "DHT community not found"})

        def on_success(values):
            request.write(json.dumps({"stored": True}))
            request.finish()

        def on_failure(failure):
            request.setResponseCode(http.INTERNAL_SERVER_ERROR)
            request.write(json.dumps({
                u"error": {
                    u"handled": True,
                    u"code": failure.value.__class__.__name__,
                    u"message": failure.value.message
                }
            }))

        parameters = http.parse_qs(request.content.read(), 1)
        if 'value' not in parameters:
            request.setResponseCode(http.BAD_REQUEST)
            return json.dumps({"error": "incorrect parameters"})

        deferred = self.dht.store_value(self.key, unhexlify(parameters['value'][0]), sign=True)
        deferred.addCallback(on_success)
        deferred.addErrback(on_failure)

        return NOT_DONE_YET
