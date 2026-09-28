import pathlib
import sys
import unittest
from unittest import mock

from flask import Flask
from werkzeug.exceptions import Forbidden, NotFound


SERVER_DIR = pathlib.Path(__file__).resolve().parents[1]
if str(SERVER_DIR) not in sys.path:
    sys.path.insert(0, str(SERVER_DIR))

from routes import home


OFFER = (
    "v=0\r\n"
    "a=fingerprint:sha-256 00:11\r\n"
    "a=ice-ufrag:warden\r\n"
    "a=setup:actpass\r\n"
)


class HomeNodePeerP2PTests(unittest.TestCase):
    def setUp(self):
        self.app = Flask(__name__)
        self.source = {"id": "source-node", "company_id": "tenant-a"}

    def test_replica_can_offer_only_to_its_p2p_writer(self):
        peer = {
            "target_node_id": "writer-node",
            "connection_mode": "p2p",
        }
        with self.app.test_request_context(
            "/api/home-node/p2p/offer",
            method="POST",
            json={"target_node_id": "writer-node", "offer_sdp": OFFER},
        ), mock.patch.object(home, "_node_auth", return_value=self.source), \
                mock.patch.object(home, "check_rate_limit", return_value=True), \
                mock.patch.object(home.db, "get_home_spaces", return_value=[]), \
                mock.patch.object(home, "replication_config_for", return_value=[peer]), \
                mock.patch.object(
                    home.db, "create_home_node_p2p_session",
                    return_value={"id": "session-a"},
                ) as create, \
                mock.patch.object(home.db, "log_home_access"):
            response = home.create_node_p2p_offer()

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.get_json()["session_id"], "session-a")
        create.assert_called_once_with(
            "tenant-a", "source-node", "writer-node", OFFER,
        )

    def test_replica_cannot_offer_to_unassigned_node(self):
        with self.app.test_request_context(
            "/api/home-node/p2p/offer",
            method="POST",
            json={"target_node_id": "other-node", "offer_sdp": OFFER},
        ), mock.patch.object(home, "_node_auth", return_value=self.source), \
                mock.patch.object(home, "check_rate_limit", return_value=True), \
                mock.patch.object(home.db, "get_home_spaces", return_value=[]), \
                mock.patch.object(home, "replication_config_for", return_value=[]):
            with self.assertRaises(Forbidden):
                home.create_node_p2p_offer()

    def test_peer_result_is_bound_to_initiating_node_and_organization(self):
        session = {
            "company_id": "tenant-a", "status": "answered",
            "answer_sdp": "answer", "error_message": None,
        }
        with self.app.test_request_context(
            "/api/home-node/p2p/result",
            method="POST",
            json={"session_id": "session-a"},
        ), mock.patch.object(home, "_node_auth", return_value=self.source), \
                mock.patch.object(
                    home.db, "get_home_p2p_session", return_value=session,
                ) as get_session:
            response = home.get_node_p2p_result()

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.get_json()["status"], "answered")
        get_session.assert_called_once_with(
            "session-a", initiator_node_id="source-node",
        )

        with self.app.test_request_context(
            "/api/home-node/p2p/result",
            method="POST",
            json={"session_id": "session-a"},
        ), mock.patch.object(home, "_node_auth", return_value=self.source), \
                mock.patch.object(
                    home.db, "get_home_p2p_session",
                    return_value={**session, "company_id": "tenant-b"},
                ):
            with self.assertRaises(NotFound):
                home.get_node_p2p_result()


if __name__ == "__main__":
    unittest.main()
