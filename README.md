# Dependent Build Server

This server provides webhook endpoints for both GitHub and Travis-CI to
facilitate testing of dependent packages.

Typical use case: you have a library and an application that uses the library.
Every time you upgrade the library, you also want to run the Travis-CI tests
for the app.

