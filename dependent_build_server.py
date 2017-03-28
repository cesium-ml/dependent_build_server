import tornado.web
import tornado.wsgi
import tornado.escape

import toml
import requests
import github

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

    def success(self, message='', payload={}):
        self.write({'status': 'success', 'message': message, 'data': payload})


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

        if event_type == 'ping':
            return self.success('Hello GitHub!')

        elif event_type != 'pull_request':
            return self.error('Unknown event sent to WebHook--expecing '
                              'pull_request')

        pr = payload["pull_request"]
        gh = github.Github(personal_token)

        head_repo = pr["head"]["repo"]["full_name"]
        base_repo = pr["base"]["repo"]["full_name"]
        commit_sha = pr['head']['sha']
        commit_branch = pr['head']['ref']

        triggered_repo = [
                d['triggered_repo'] for d in config['dependent_repo']
                if d['source_repo'] == base_repo
                ]

        if len(triggered_repo) == 0:
            return self.error('No dependent repo set for ' \
                              '{}'.format(repo))

        # For now, we only support one triggered repo
        triggered_repo = triggered_repo[0]

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
                        "global": [
                            "TRIGGERED_FROM_REPO={}".format(head_repo),
                            "TRIGGERED_FROM_SHA={}".format(commit_sha),
                            "TRIGGERED_FROM_BRANCH={}".format(commit_branch)
                            ]
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
            triggered_repo.replace('/', '%2F') + '/requests',
            headers={'Travis-API-Version': '3',
                     'Authorization': 'token "{}"'.format(travis_token)},
            json=build)

        if r.status_code != 202:
            return self.error('Failed to create Travis-CI build')


        # Add CI status to PR
        repo = gh.get_repo(base_repo)
        commit = repo.get_commit(commit_sha)
        commit.create_status(
                'pending',
                target_url='https://travis-ci.org/' + triggered_repo + \
                           '/builds',
                description='Triggered Travis-CI build ' \
                            'of {}'.format(triggered_repo),
                context='continuous-integration/dependent-build-server')

        self.success()


temp_log = []

class TravisHandler(BaseHandler):
    def post(self):
        # Verify the payload
        payload = self.get_body_argument("payload")

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

        # Now decode and process
        payload = tornado.escape.json_decode(payload)

        status = ("error" if (payload["status"] == "1")
                  else "success")

        sha = [f for f in payload["config"]["global_env"]
               if 'TRIGGERED_FROM_SHA' in f][0]
        sha = sha.split('=')[1]

        triggered_repo = payload["repository"]["owner_name"] + "/" + \
                         payload["repository"]["name"]

        source_repo = [
                d['source_repo'] for d in config['dependent_repo']
                if d['triggered_repo'] == triggered_repo
                ][0]

        gh = github.Github(config["github"]["personal_access_token"])
        repo = gh.get_repo(source_repo)
        commit = repo.get_commit(sha)
        commit.create_status(
                status,
                target_url=payload["build_url"],
                description='Dependent build completed',
                context='continuous-integration/dependent-build-server')


class Debug(BaseHandler):
    def get(self):
        self.write('\n'.join(temp_log))


application = tornado.wsgi.WSGIApplication([
    (r"/", MainHandler),
    (r"/webhook", WebhookHandler),
    (r"/travis", TravisHandler),
    (r"/debug", Debug)
])
