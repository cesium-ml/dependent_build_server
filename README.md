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

