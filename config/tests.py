from unittest.mock import patch

import redis
from django.core.management import call_command
from django.test import TestCase


class HealthTests(TestCase):
    def test_health_and_readiness_report_dependency_failure(self):
        call_command("init_storage", verbosity=0)
        self.assertEqual(self.client.get("/healthz/").json(), {"status": "ok"})
        with patch("config.health.redis.Redis.from_url") as connect:
            connection = connect.return_value.__enter__.return_value
            self.assertEqual(self.client.get("/readyz/").json(), {"status": "ready"})
            connection.ping.side_effect = redis.ConnectionError("Test unavailable")
            with self.assertLogs("config.health", level="WARNING"):
                response = self.client.get("/readyz/")
            self.assertEqual(response.status_code, 503)
            self.assertEqual(response.json(), {"status": "unavailable"})
