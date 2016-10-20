import tornado.web
import tornado.wsgi
import tornado.escape

import toml
import requests

import os
import sys
import hmac


if not os.path.exists('config.toml'):
    print('No config file found---please refer to the README')
    sys.exit(1)

config = toml.load('config.toml')


def verify_signature(payload, signature, secret):
    expected = 'sha1=' + hmac.new(secret.encode('ascii'),
                                  payload).hexdigest()

    return hmac.compare_digest(signature, expected)


class MainHandler(tornado.web.RequestHandler):
    def get(self):
        self.write("Hello from Tornado")


class WebhookHandler(tornado.web.RequestHandler):
    def get(self):
        self.write('Webhook alive and listening')

    def post(self):
        if not verify_signature(self.request.body,
                                self.request.headers.get('X-Hub-Signature'),
                                config['github']['webhook_secret']):
            return self.write(
                    {'status': 'error',
                     'message': 'Cannot validate GitHub payload with ' \
                                'provided WebHook secret'})

        json = tornado.escape.json_decode(self.request.body)
        payload = json["payload"]
        personal_token = config['github']['personal_access_token']

        event_type = self.request.headers.get('X-GitHub-Event')


        if event_type == 'pull_request':
            pr = payload["pull_request"]
            gh = github.Github(personal_token)
            repo = gh.get_repo(pr["repo"]["full_name"])
            commit = repo.get_commit(pr['head']['sha'])

            dependent_repo = [d['triggered_repo'] for d in config['dependent_repo']
                              if d['source_repo'] == repo]

            if len(dependent_repo) == 0:
                return self.write({'status': 'error',
                                   'message': 'No dependent repo set for ' \
                                              '{}'.format(repo)})

            # For now, we only support one triggered repo
            dependent_repo = dependent_repo[0]

            commit.create_status(
                    'pending',
                    target_url=config['server']['url'] + '/travis',
                    description='Triggering Travis-CI build ' \
                                'of {}'.format(dependent_repo),
                    context='continuous-integration/dependent-build-server')


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
                self.write({'status': 'error',
                            'message': 'Failed to create Travis-CI build'})

        else:
            pass

        self.write({'status': 'OK'})


class TravisHandler(tornado.web.RequestHandler):
    def post(self):
        json = tornado.escape.json_decode(self.request.body)


application = tornado.wsgi.WSGIApplication([
    (r"/", MainHandler),
    (r"/webhook", WebhookHandler),
    (r"/travis", TravisHandler)
])
