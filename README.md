# Dependent Build Server

This server provides webhook endpoints for both GitHub and Travis-CI to
facilitate testing of dependent packages.

Typical use case: you have a library and an application that uses the library.
Every time you upgrade the library, you also want to run the Travis-CI tests
for the app.

Three environment variables are set for the Travis-CI build:

- `TRIGGERED_FROM_REPO`: repository that triggered the build, e.g. cesium-ml/cesium
- `TRIGGERED_FROM_SHA`: SHA that triggered the build
- `TRIGGERED_FROM_BRANCH`: branch name of the PR that triggered the build

## Configuration

The dependent build server is configured in `config.toml`.  Please
see `config.toml.example` for a commented example.

### webhook

On the GitHub side, you will need to install the webhook *on the
triggering repository* (i.e., when a PR is made against this repo, it
will start a build on another, dependent, repo):

1. Go to `https://github.com/my_org/my_triggering_repo`
2. Settings -> webhooks -> Add webhook
3. Configure the webhook:
   - **Payload URL**: `http://my.server.com/webhook` (here, I assume
     that the dependent build server is hosted on
     `http://my.server.com/` (at the root).
   - **Content type**: `application/json`
   - **Secret**: A string of your choice, e.g. generated using
     `binascii.hexlify(os.urandom(24))`.  This value **must be added
     to `config.toml`**.
   - **Which events would you like to trigger this webhook?**:
     - Choose "Let me select individual events"
     - Pull request

### Personal access token

Go to your GitHub profile settings at
`https://github.com/settings/profile`, and click on "Personal Access
Tokens".  Generate a new token:

- **Token description:** dependent_build_server (or another name of
  your choosing)
- **Select scopes:** Check `repo:status`, `repo_deployment`,
  `public_repo`.

Add the personal access token value to `config.toml`.
