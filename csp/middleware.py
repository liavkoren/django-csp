from __future__ import absolute_import

from collections import defaultdict
from functools import partial

from django.conf import settings
from django.utils.crypto import get_random_string
from django.utils.functional import SimpleLazyObject

try:
    from django.utils.six.moves import http_client
except ImportError:
    # django 3.x removed six
    import http.client as http_client

try:
    from django.utils.deprecation import MiddlewareMixin
except ImportError:
    class MiddlewareMixin(object):
        """
        If this middleware doesn't exist, this is an older version of django
        and we don't need it.
        """
        pass

from .utils import (
    build_policy, DEFAULT_EXCLUDE_URL_PREFIXES, HTTP_HEADERS,
)


EXEMPTED_DEBUG_CODES = {
    http_client.INTERNAL_SERVER_ERROR,
    http_client.NOT_FOUND,
}


class CSPMiddleware(MiddlewareMixin):
    """
    Implements the Content-Security-Policy response header, which
    conforming user-agents can use to restrict the permitted sources
    of various content.

    See http://www.w3.org/TR/CSP/

    """
    def _make_nonce(self, request, length=16):
        # Ensure that any subsequent calls to request.csp_nonce return the
        # same value
        if not getattr(request, '_csp_nonce', None):
            request._csp_nonce = get_random_string(length)
        return request._csp_nonce

    def process_request(self, request):
        nonce = partial(self._make_nonce, request)
        request.csp_nonce = SimpleLazyObject(nonce)

    def process_response(self, request, response):
        if getattr(response, '_csp_exempt', False):
            return response

        # Check for ignored path prefix.
        # TODO: Legacy setting
        prefixes = getattr(
            settings,
            'CSP_EXCLUDE_URL_PREFIXES',
            DEFAULT_EXCLUDE_URL_PREFIXES,
        )
        if request.path_info.startswith(prefixes):
            return response

        # Check for debug view
        if response.status_code in EXEMPTED_DEBUG_CODES and settings.DEBUG:
            return response

        existing_headers = {
            header for header in HTTP_HEADERS if header in response
        }
        if len(existing_headers) == len(HTTP_HEADERS):
            # Don't overwrite existing headers.
            return response

        # These won't be ordered properly on Cpython 3.5 or below
        # (out of support October 2020)
        headers = defaultdict(list)

        for csp, report_only in self.build_policy(request, response):
            header = HTTP_HEADERS[int(report_only)]
            if header in existing_headers:  # don't overwrite
                continue
            headers[header].append(csp)

        for header, policies in headers.items():
            # TODO: Design Decision do we want the optional whitespace?
            # Maybe only in DEBUG mode?
            response[header] = ', '.join(policies)
        return response

    def build_policy(self, request, response):
        build_kwargs = {
            key: getattr(response, '_csp_%s' % key, None)
            for key in ('config', 'update', 'replace', 'order')
        }
        return build_policy(
            nonce=getattr(request, '_csp_nonce', None),
            **build_kwargs,
        )
