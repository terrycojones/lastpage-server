from oauth2 import Token, Request, Consumer, SignatureMethod_HMAC_SHA1

from twisted.python import log
from twisted.web import client

from txretry.retry import RetryingCall


def getTwitterOAuthURL(conf, oauthTokenDict):
    """
    Obtain a URL from twitter.com that we can redirect a user to so they
    can authenticate themselves and authorize loveme.do to act on their
    behalf.

    @param conf: the lovemedo configuration.
    @param oauthTokenDict: A C{dict} mapping token keys to tokens.
    @return: A C{Deferred} that fires with the URL for OAuth verification.
    """
    log.msg('Got login URL request.')

    def _makeURL(result):
        token = Token.from_string(result)
        # Store the token by key so we can find it when the callback comes.
        oauthTokenDict[token.key] = token
        request = Request.from_token_and_callback(
            token=token, http_url=conf.authorization_url)
        url = request.to_url()
        log.msg('Browser OAuth redirect URL = %r' % url)
        return url

    consumer = Consumer(conf.consumer_key, conf.consumer_secret)
    request = Request.from_consumer_and_token(
        consumer, callback=conf.callback_url,
        http_url=conf.request_token_url)
    request.sign_request(SignatureMethod_HMAC_SHA1(), consumer, None)
    r = RetryingCall(
        client.getPage, conf.request_token_url, headers=request.to_header())
    d = r.start()
    d.addCallback(_makeURL)
    d.addErrback(log.err)
    return d
