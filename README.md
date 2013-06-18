Squiz Auth
=========

Squiz Auth is a Login / SSO system designed to authenticate users against one or more LDAP servers, and then pass their details off to a third party system via one or more SSO systems.

At the moment only [JWT](http://tools.ietf.org/html/draft-ietf-oauth-json-web-token-08) (JSON Web Tokens) is implemented. 

Squiz Auth is written in Python, using the Flask web framework and runs ideally with uWSGI behind nginx.

Instructions
------------

#### Install
```sh
GIT_PATH=https://github.com/squizuk/squiz-auth.git
AUTH_PATH=/opt/squiz-auth/
git clone $GIT_PATH $AUTH_PATH
cd $AUTH_PATH
virtualenv $PWD
bin/pip install -r requirements.txt
mv app/sample-config.yaml app/config.yaml && vim app/config.yaml
```

#### Test
```
bin/uwsgi -H $PWD -s /tmp/squiz_auth.sock --file app/auth.py --callable app -M --need-app
```

#### Production
6. Install supervisor
7. Use example supervisor config at /path/to/git-repo/contrib/supervisor
8. Setup uwsgi in nginx (google it)

Version
-------

0.5


TODO
----
 - More SSO systems where required
 - Better feedback on login failures
 - Better separation of code rather than single-file
 -

Copyright & License
-------------------

The bundled software components are copyrighted by the respective copyright holders.

The core software is licensed under the 2-clause BSD license.

Copyright (c) 2013, Ben Agricola <bagricola@squiz.co.uk>

All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are
met:

* Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.
* Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer in the documentation and/or other materials provided with the distribution.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS
IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED
TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A
PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED
TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

