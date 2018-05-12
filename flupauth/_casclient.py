import xml.dom.minidom

import requests


__all__ = ['CASClient']


CAS_NAMESPACE_URI = 'http://www.yale.edu/tp/cas'


class CASClient(object):
    """
    Simple CAS client.

    validateUrl - CAS server validation URL, e.g.
      https://www.example.com/cas/serviceValidate

    serviceUrl - Associated service URL.
    """
    def __init__(self, validateUrl, serviceUrl):
        self.validateUrl = validateUrl
        self.serviceUrl = serviceUrl

    def authenticate(self, ticket):
        """
        Authenticate a ticket. Either returns the authenticated username
        or None.
        """
        r = requests.get(self.validateUrl, params={
            'service': self.serviceUrl,
            'ticket': ticket
        }, timeout=10)
        r.raise_for_status()
        result = r.text

        dom = xml.dom.minidom.parseString(result)
        username = None
        nodes = dom.getElementsByTagNameNS(CAS_NAMESPACE_URI, 'authenticationSuccess')
        if nodes:
            successNode = nodes[0]
            nodes = successNode.getElementsByTagNameNS(CAS_NAMESPACE_URI, 'user')
            if nodes:
                userNode = nodes[0]
                if userNode.firstChild is not None:
                    username = userNode.firstChild.nodeValue
        dom.unlink()

        return username
