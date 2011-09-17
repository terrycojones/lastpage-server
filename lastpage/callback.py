# Copyright 2011 Fluidinfo Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License"); you
# may not use this file except in compliance with the License.  You
# may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.  See the License for the specific language governing
# permissions and limitations under the License.

import json
import uuid

from lastpage.agent import ResponseConsumer

from oauth2 import Token, Request, Consumer, SignatureMethod_HMAC_SHA1

from twisted.internet import reactor
from twisted.python import log
from twisted.web import resource, client, server
from twisted.web.client import Agent
from twisted.web.http_headers import Headers


class Callback(resource.Resource):
    """
    Handles a callback requests from Twitter's OAuth endpoint.

    @param cookieDict: A C{dict} mapping cookie values to Twitter usernames.
    @param oauthTokenDict: A C{dict} mapping OAuth keys to tokens.
    @param conf: A L{config.Config} instance holding configuration
        settings.
    @param agent: The C{twisted.web.client.Agent} instance to use when making
        HTTP requests to the API endpoint.
    """
    isLeaf = True

    def __init__(self, cookieDict, oauthTokenDict, conf, agent=None):
        self._conf = conf
        self._cookieDict = cookieDict
        self._oauthTokenDict = oauthTokenDict
        self._agent = agent or Agent(reactor)

    def render_GET(self, request):
        """
        Handles a callback GET request.

        @param request: A twisted.web HTTP C{Request}.
        """
        log.err('Callback received: %s' % request)

        oauthToken = request.args['oauth_token']
        if oauthToken:
            oauthToken = oauthToken[0]
        else:
            log.err('Received callback with no oauth_token: %s' % request)
            raise Exception('Received callback with no oauth_token.')

        oauthVerifier = request.args['oauth_verifier']
        if oauthVerifier:
            oauthVerifier = oauthVerifier[0]
        else:
            log.err('Received callback with no oauth_verifier: %s' % request)
            raise Exception('Received callback with no oauth_verifier.')

        try:
            token = self._oauthTokenDict.pop(oauthToken)
        except KeyError:
            log.err('Received callback with unknown oauth_token: %s' %
                    oauthToken)
            raise Exception('Received callback with unknown oauth_token.')

        conf = self._conf
        consumer = Consumer(conf.consumer_key, conf.consumer_secret)
        oauthRequest = Request.from_consumer_and_token(
            consumer, token=token, http_url=conf.access_token_url)
        oauthRequest.sign_request(
            SignatureMethod_HMAC_SHA1(), consumer, token)
        log.msg('Requesting access token.')
        headers = {}
        for header, value in oauthRequest.to_header().iteritems():
            headers[header] = str(value)
        d = client.getPage(str(oauthRequest.to_url()), headers=headers)
        d.addCallback(self._storeAccessToken, request)
        d.addErrback(log.err)
        return server.NOT_DONE_YET

    def _storeAccessToken(self, result, request):
        """Store a Twitter access token and begin a verify credentials call.

        @param result: A C{str} containing a Twitter access token.
        @param request: A twisted.web HTTP C{Request}.
        @return: A C{Deferred} that will fire with the result of calling
            verify credentials (or an OAuth Echo endpoint which will proxy
            the verify credentials request.
        """
        accessToken = Token.from_string(result)
        log.msg('Got access token: %s' % accessToken)
        conf = self._conf
        consumer = Consumer(conf.consumer_key, conf.consumer_secret)
        oauthRequest = Request.from_consumer_and_token(
            consumer, token=accessToken, http_url=conf.verify_credentials_url)
        oauthRequest.sign_request(
            SignatureMethod_HMAC_SHA1(), consumer, accessToken)
        log.msg('Verifying credentials.')
        if conf.oauth_echo_url:
            # Make an OAuth Echo request instead of calling
            # VerifyCredentials ourselves directly.
            authHeader = str(oauthRequest.to_header(
                conf.verify_credentials_url)['Authorization'])
            headers = Headers({
                'X-Auth-Service-Provider': [conf.verify_credentials_url],
                'X-Verify-Credentials-Authorization': [authHeader],
                })
            url = conf.oauth_echo_url
        else:
            headers = Headers()
            url = str(oauthRequest.to_url())
        d = self._agent.request('GET', url, headers)
        d.addCallbacks(self._consumeResponse, self._verifyCredentialsError,
                       callbackArgs=[accessToken, request],
                       errbackArgs=[request])
        d.addErrback(log.err)
        return d

    def _verifyCredentialsError(self, fail, request):
        """
        Credentials could not be verified. Log the error and redirect the
        user to the failed login URL.

        @param fail: a twisted.python C{Failure} instance.
        @param request: A twisted.web HTTP C{Request}.
        """
        log.msg('Agent could not set up connection for verify credentials:')
        log.err(fail.value)
        log.msg('Redirect to %s' % self._conf.login_failure_redirect_url)
        request.redirect(self._conf.login_failure_redirect_url)
        request.finish()

    def _consumeResponse(self, response, accessToken, request):
        """Read HTTP response data from the verify credentials call.

        If the response is successful (code 200), arrange for the body to be
        retrieved and delivered to self._storeUser. If not, log an error
        including any X-FluidDB headers, and redirect the user to the
        login failed URL.

        @param response: A twisted.web.client C{Response}.
        @param accessToken: A C{str} access token from Twitter.
        @param request: A twisted.web HTTP C{Request}.
        """
        if response.code == 200:
            consumer = ResponseConsumer()
            consumer.deferred.addCallback(self._storeUser, accessToken,
                                          request)
            response.deliverBody(consumer)
            return consumer.deferred
        else:
            log.msg('Received non-200 %d status (%s) on verify credentials '
                    'call.' % (response.code, response.phrase))
            for header, value in response.headers.getAllRawHeaders():
                if header.lower().startswith('x-fluiddb'):
                    log.msg('Response header %r = %r.' % (header, value))
            log.msg('Redirect to %s' % self._conf.login_failure_redirect_url)
            request.redirect(self._conf.login_failure_redirect_url)
            request.finish()

    def _storeUser(self, result, accessToken, request):
        """Decode the user data from verify credentials and store it
        locally.  Push a cookie to the client that will let us find the
        login information when they return.  Redirect the request to the
        logged in page.

        @param result: the JSON C{str} from the verify credentials call.
        @param accessToken: A C{str} access token from Twitter.
        @param request: A twisted.web HTTP C{Request}.
        """
        user = json.loads(result)
        key = str(uuid.uuid4())
        conf = self._conf
        self._cookieDict[key] = (user, accessToken)
        log.msg('Setting cookie %s' % key)
        request.addCookie(conf.cookie_name, key, path='/',
                          domain=conf.cookie_domain)
        request.redirect(conf.logged_in_redirect_url)
        log.msg('Redirecting to %s' % conf.logged_in_redirect_url)
        request.finish()
