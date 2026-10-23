import io
import json
import unittest
from urllib.error import HTTPError
from urllib.parse import parse_qs, urlsplit
from unittest.mock import patch

from certbot import errors
from certbot_dns_cpanel import dns_cpanel


def reply(payload):
    return io.BytesIO(json.dumps(payload).encode('utf-8'))


class SessionAuthenticationTests(unittest.TestCase):
    def test_session_used_for_dns_lookup_add_and_cleanup(self):
        calls = []

        def serve(request, timeout):
            calls.append(request)
            self.assertEqual(timeout, 30)
            self.assertIsNone(request.get_header('Authorization'))
            parts = urlsplit(request.full_url)
            if parts.path == '/login/':
                self.assertEqual(request.get_method(), 'POST')
                self.assertEqual(parse_qs(request.data.decode()),
                                 {'user': ['account'], 'pass': ['p&ss=word+!']})
                return reply({'status': 1, 'security_token': '/cpsess1234567890'})
            self.assertEqual(parts.path, '/cpsess1234567890/json-api/cpanel')
            query = parse_qs(parts.query)
            function = query['cpanel_jsonapi_func'][0]
            if function == 'fetchzones':
                data = [{'zones': {'example.com': 1}}]
            elif function == 'fetchzone_records':
                data = [{'line': 5}, {'line': 8}]
            else:
                if function == 'add_zone_record':
                    self.assertEqual(query['name'], ['_acme-challenge'])
                    self.assertEqual(query['txtdata'], ['challenge'])
                data = [{'result': {'status': 1}}]
            return reply({'cpanelresult': {'data': data}})

        with patch.object(dns_cpanel, 'build_opener') as factory:
            factory.return_value.open.side_effect = serve
            client = dns_cpanel._CPanelClient('https://panel.example.com:2083/',
                                             'account', 'p&ss=word+!', None)
            with self.assertLogs(dns_cpanel.logger, level='DEBUG') as logs:
                client.add_txt_record('_acme-challenge.example.com', 'challenge')
                client.del_txt_record('_acme-challenge.example.com', 'challenge')
            self.assertNotIn('cpsess1234567890', '\n'.join(logs.output))
            self.assertNotIn('p&ss=word+!', '\n'.join(logs.output))
            self.assertEqual(sum(urlsplit(r.full_url).path == '/login/' for r in calls), 1)
            removals = [parse_qs(urlsplit(r.full_url).query) for r in calls
                        if 'remove_zone_record' in r.full_url]
            self.assertEqual([q['line'] for q in removals], [['8'], ['5']])

    def test_token_authentication_skips_login(self):
        with patch.object(dns_cpanel, 'build_opener') as factory:
            factory.return_value.open.return_value = reply(
                {'cpanelresult': {'data': [{'zones': {'example.com': 1}}]}})
            client = dns_cpanel._CPanelClient('https://panel.example.com:2083',
                                             'account', 'unused-password', 'api-token')
            factory.return_value.open.assert_not_called()
            self.assertEqual(client._get_zone_and_name('_acme-challenge.example.com'),
                             ('example.com', '_acme-challenge'))
            request = factory.return_value.open.call_args.args[0]
            self.assertEqual(request.get_header('Authorization'), 'cpanel account:api-token')
            self.assertEqual(urlsplit(request.full_url).path, '/json-api/cpanel')

    def test_failed_login_and_invalid_session_stop_api_requests(self):
        for result in [[], {'status': 0}, {'status': 1},
                       {'status': 1, 'security_token': '//other.example.com'},
                       {'status': 1, 'security_token': '/cpsess123?injected=1'}]:
            with self.subTest(result=result), patch.object(dns_cpanel, 'build_opener') as factory:
                factory.return_value.open.return_value = reply(result)
                with self.assertRaises(errors.PluginError):
                    dns_cpanel._CPanelClient('https://panel.example.com', 'account', 'password', None)
                self.assertEqual(factory.return_value.open.call_count, 1)

    def test_http_error_does_not_expose_session_url(self):
        with patch.object(dns_cpanel, 'build_opener') as factory:
            factory.return_value.open.side_effect = [
                reply({'status': 1, 'security_token': '/cpsess1234567890'}),
                HTTPError('https://panel.example.com/cpsess1234567890/json-api/cpanel',
                          403, 'Forbidden', {}, None),
            ]
            client = dns_cpanel._CPanelClient('https://panel.example.com', 'account', 'password', None)
            with self.assertRaises(errors.PluginError) as caught:
                client._get_zone_and_name('example.com')
            self.assertEqual(str(caught.exception), 'cPanel ZoneEdit.fetchzones failed (HTTP 403)')

    def test_client_reused_across_challenges(self):
        plugin = object.__new__(dns_cpanel.CpanelConfigurator)
        plugin.credentials = unittest.mock.Mock()
        plugin._cpanel_client = None
        with patch.object(dns_cpanel, '_CPanelClient') as factory:
            self.assertIs(plugin._get_cpanel_client(), plugin._get_cpanel_client())
            factory.assert_called_once()

    def test_http_url_rejected_before_login(self):
        with patch.object(dns_cpanel, 'build_opener') as factory:
            with self.assertRaises(errors.PluginError):
                dns_cpanel._CPanelClient('http://panel.example.com', 'account', 'password', None)
            factory.assert_not_called()


if __name__ == '__main__':
    unittest.main()
