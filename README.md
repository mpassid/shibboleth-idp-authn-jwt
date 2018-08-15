# Shibboleth IdP v3: JWT authentication

[![License](http://img.shields.io/:license-mit-blue.svg)](https://opensource.org/licenses/MIT)
[![Build Status](https://travis-ci.org/mpassid/shibboleth-idp-authn-jwt.svg?branch=master)](https://travis-ci.org/mpassid/shibboleth-idp-authn-jwt)
[![Coverage Status](https://coveralls.io/repos/github/mpassid/shibboleth-idp-authn-jwt/badge.svg?branch=master)](https://coveralls.io/github/mpassid/shibboleth-idp-authn-jwt?branch=master)

## Overview

This module implements an authentication flow for [Shibboleth Identity Provider v3](https://wiki.shibboleth.net/confluence/display/IDP30/Home) exploiting attributes provided by 
3rd party via JWT token.

## Prerequisities and compilation

- Java 7+
- [Apache Maven 3](https://maven.apache.org/)

```
mvn package
```

After successful compilation, the _target_ directory contains _shibboleth-idp-authn-jwt-\<version\>.zip archive.

## Deployment

After compilation, the module's JAR-files must be deployed to the IdP Web
application. Also, the module's authentication flow and its bean definitions must
be deployed to the IdP. Depending on the IdP installation, the module deployment may be achieved for instance 
with the following sequence:

```
unzip target/shibboleth-idp-authn-jwt-<version>.zip
cp shibboleth-idp-authn-jwt-<version>/edit-webapp/WEB-INF/lib/* /opt/shibboleth-idp/edit-webapp/WEB-INF/lib
cp -r shibboleth-idp-authn-jwt-<version>/flows/* /opt/shibboleth-idp/flows
cd /opt/shibboleth-idp
sh bin/build.sh
```

The final command will rebuild the _war_-package for the IdP application.

TODO: Finalize documentation
