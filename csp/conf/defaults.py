POLICIES = ['default']

UPDATE_TEMPLATE = 'default'

EXCLUDE_URL_PREFIXES = ()

POLICY_DEFINITIONS = {
    'default': {
        # Fetch Directives
        'child-src': None,
        'connect-src': None,
        'default-src': ("'self'",),
        'script-src': None,
        'script-src-attr': None,
        'script-src-elem': None,
        'object-src': None,
        'style-src': None,
        'style-src-attr': None,
        'style-src-elem': None,
        'font-src': None,
        'frame-src': None,
        'img-src': None,
        'manifest-src': None,
        'media-src': None,
        'prefetch-src': None,
        'worker-src': None,
        # Document Directives
        'base-uri': None,
        'plugin-types': None,
        'sandbox': None,
        # Navigation Directives
        'form-action': None,
        'frame-ancestors': None,
        'navigate-to': None,
        # Reporting Directives
        'report-uri': None,
        'report-to': None,
        'require-sri-for': None,
        # Other Directives
        'upgrade-insecure-requests': False,
        'block-all-mixed-content': False,
        # Pseudo Directives
        'report_only': False,
        'include_nonce_in': ('default-src',),
    }
}
