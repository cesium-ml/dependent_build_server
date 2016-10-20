import tornado.web
import tornado.wsgi
import tornado.escape

import toml
import requests

import os
import sys
import hmac
import base64

from OpenSSL import crypto


if not os.path.exists('config.toml'):
    print('No config file found---please refer to the README')
    sys.exit(1)

config = toml.load('config.toml')


def verify_signature(payload, signature, secret):
    expected = 'sha1=' + hmac.new(secret.encode('ascii'),
                                  payload, 'sha1').hexdigest()

    return hmac.compare_digest(signature, expected)


class BaseHandler(tornado.web.RequestHandler):
    def error(self, message):
        self.set_status(500)
        self.write({'status': 'error', 'message': message})

    def success(self, payload={}):
        self.write({'status': 'success', 'data': payload})


class MainHandler(BaseHandler):
    def get(self):
        self.write("Hello from Tornado")


class WebhookHandler(BaseHandler):
    def get(self):
        self.write('Webhook alive and listening')

    def post(self):
        if not 'X-Hub-Signature' in self.request.headers:
            return self.error('WebHook not configured with secret')

        if not verify_signature(self.request.body,
                                self.request.headers['X-Hub-Signature'],
                                config['github']['webhook_secret']):
            return self.error('Cannot validate GitHub payload with ' \
                                'provided WebHook secret')

        payload = tornado.escape.json_decode(self.request.body)
        personal_token = config['github']['personal_access_token']

        event_type = self.request.headers['X-GitHub-Event']


        if event_type == 'pull_request':
            pr = payload["pull_request"]
            gh = github.Github(personal_token)
            repo = gh.get_repo(pr["repo"]["full_name"])
            commit = repo.get_commit(pr['head']['sha'])

            dependent_repo = [d['triggered_repo'] for d in config['dependent_repo']
                              if d['source_repo'] == repo]

            if len(dependent_repo) == 0:
                return self.error('No dependent repo set for ' \
                                  '{}'.format(repo))

            # For now, we only support one triggered repo
            dependent_repo = dependent_repo[0]

            travis_headers = {
                'User-Agent': 'Travis-dependent_build_server/0.0'
            }
            travis_api = 'https://api.travis-ci.org'

            travis_token = requests.post(
                    travis_api + '/auth/github',
                    headers=travis_headers,
                    json={'github_token': personal_token}).json()
            travis_token = travis_token['access_token']

            build = {
                "request": {
                    "message": "Build triggered by dependent_build_server",
                    "branch": "master",
                    "config": {
                        "env": {
                            "matrix": ["CESIUM_REPO={}".format(),
                                       "CESIUM_SHA={}".format()]
                        },
                        "notifications": {
                            "webhooks": [
                                config['server']['url'] + '/travis'
                                ],
                        }
                    }
                }
            }

            r = requests.post(
                travis_api + '/repo/' + \
                repo.replace('/', '%2F') + '/requests',
                headers={'Travis-API-Version': '3',
                         'Authorization': 'token "{}"'.format(travis_token)},
                json=build)

            if r.status_code != 202:
                self.error('Failed to create Travis-CI build')

            commit.create_status(
                    'pending',
                    target_url='https://travis-ci.org/' + dependent_repo,
                    description='Triggered Travis-CI build ' \
                                'of {}'.format(dependent_repo),
                    context='continuous-integration/dependent-build-server')
        else:
            self.error('Unknown event sent to WebHook')

        self.write({'status': 'OK'})


class TravisHandler(BaseHandler):
    def post(self):
        payload = tornado.escape.json_decode(self.request.body)
        signature = base64.b64decode(
                self.request.headers.get('Signature')
                )

        status = requests.get('https://api.travis-ci.org/config').json()
        pubkey = status['config']['notifications']['webhook']['public_key']

        public_key = crypto.load_publickey(crypto.FILETYPE_PEM, pubkey)
        certificate = crypto.X509()
        certificate.set_pubkey(public_key)

        try:
            crypto.verify(certificate, signature, payload, 'sha1')
        except crypto.Error:
            return self.error('Invalid signature for Travis payload')

        status = ("error" if (payload["status"] == "1")
                  else "success")
        commit = payload["commit"]
        repo = payload["repository"]["owner_name"] + "/" + \
               payload["repository"]["name"]

        gh = github.Github(config["github"]["personal_access_token"])
        repo = gh.get_repo(repo)
        commit = repo.get_commit(commit)
        commit.create_status(
                status,
                target_url=payload["build_url"],
                description='Dependent build completed',
                context='continuous-integration/dependent-build-server')


application = tornado.wsgi.WSGIApplication([
    (r"/", MainHandler),
    (r"/webhook", WebhookHandler),
    (r"/travis", TravisHandler)
])
