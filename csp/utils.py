import copy
import re
import warnings

from collections import OrderedDict
from itertools import chain

from django.conf import settings
from django.utils.encoding import force_str

from .deprecation import (
    CHILD_SRC_DEPRECATION_WARNING,
    LEGACY_SETTINGS_NAMES_DEPRECATION_WARNING,
)


DEFAULT_EXCLUDE_URL_PREFIXES = ()

DEFAULT_POLICIES = ['default']

DEFAULT_UPDATE_TEMPLATE = 'default'

DEFAULT_POLICY_DEFINITIONS = {
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

HTTP_HEADERS = (
    'Content-Security-Policy',
    'Content-Security-Policy-Report-Only',
)

DIRECTIVES = set(DEFAULT_POLICY_DEFINITIONS['default'])
PSEUDO_DIRECTIVES = {d for d in DIRECTIVES if '_' in d}

# used in setting_to_directive (enables deletion updates via None)
no_value = object()


def setting_to_directive(setting, prefix='CSP_', value=no_value):
    setting = setting[len(prefix):].lower()
    if setting not in PSEUDO_DIRECTIVES:
        setting = setting.replace('_', '-')
    assert setting in DIRECTIVES

    if value is not no_value:
        if isinstance(value, str):
            value = [value]
        return setting, value
    return setting


def directive_to_setting(directive, prefix='CSP_'):
    setting = '{}{}'.format(
        prefix,
        directive.replace('-', '_').upper()
    )
    return setting


_LEGACY_SETTINGS = {
    directive_to_setting(directive) for directive in DIRECTIVES
}


def _handle_legacy_settings(definitions, defer_to_legacy=True):
    legacy_names = (
        _LEGACY_SETTINGS
        & set(s for s in dir(settings) if s.startswith('CSP_'))
    )
    if not legacy_names:
        return

    warnings.warn(
        LEGACY_SETTINGS_NAMES_DEPRECATION_WARNING % ', '.join(legacy_names),
        DeprecationWarning,
    )

    csp = definitions['default']
    legacy_csp = (
        setting_to_directive(name, value=getattr(settings, name))
        for name in legacy_names
    )
    if defer_to_legacy:
        csp.update(legacy_csp)
    else:
        csp.update((key, val) for key, val in legacy_csp if key not in csp)


def from_settings():
    policies = getattr(settings, 'CSP_POLICIES', DEFAULT_POLICIES)
    definitions = csp_definitions_update({}, DEFAULT_POLICY_DEFINITIONS)
    custom_definitions = getattr(
        settings,
        'CSP_POLICY_DEFINITIONS',
        {'default': {}},
    )
     # Technically we're modifying Django settings here,
     # but it shouldn't matter since the end result of either will be the same
    _handle_legacy_settings(custom_definitions)
    for name, csp in custom_definitions.items():
        definitions[name].update(csp)
    # TODO: Error handling
    # TODO: Remove in October 2020 when ordered dicts are the default
    return OrderedDict(
        (name, definitions[name]) for name in policies
    )


def build_policy(config=None, update=None, replace=None, nonce=None):
    """Builds the policy as a string from the settings."""

    if config is None:
        config = from_settings()
        # Be careful, don't mutate config as it could be from settings

    update = update if update is not None else {}
    replace = replace if replace is not None else {}
    csp = {}

    for k in set(chain(config, replace)):
        if k in replace:
            v = replace[k]
        else:
            v = config[k]
        if v is not None:
            v = copy.copy(v)
            if not isinstance(v, (list, tuple)):
                v = (v,)
            csp[k] = v

    for k, v in update.items():
        if v is not None:
            if not isinstance(v, (list, tuple)):
                v = (v,)
            if csp.get(k) is None:
                csp[k] = v
            else:
                csp[k] += tuple(v)

    report_uri = csp.pop('report-uri', None)

    policy_parts = {}
    for key, value in csp.items():
        # flag directives with an empty directive value
        if len(value) and value[0] is True:
            policy_parts[key] = ''
        elif len(value) and value[0] is False:
            pass
        else:  # directives with many values like src lists
            policy_parts[key] = ' '.join(value)

        if key == 'child-src':
            warnings.warn(CHILD_SRC_DEPRECATION_WARNING, DeprecationWarning)

    if report_uri:
        report_uri = map(force_str, report_uri)
        policy_parts['report-uri'] = ' '.join(report_uri)

    if nonce:
        include_nonce_in = getattr(settings, 'CSP_INCLUDE_NONCE_IN',
                                   ['default-src'])
        for section in include_nonce_in:
            policy = policy_parts.get(section, '')
            policy_parts[section] = ("%s %s" %
                                     (policy, "'nonce-%s'" % nonce)).strip()

    return '; '.join(['{} {}'.format(k, val).strip()
                      for k, val in policy_parts.items()])


def _default_attr_mapper(attr_name, val):
    if val:
        return ' {}="{}"'.format(attr_name, val)
    else:
        return ''


def _bool_attr_mapper(attr_name, val):
    # Only return the bare word if the value is truthy
    # ie - defer=False should actually return an empty string
    if val:
        return ' {}'.format(attr_name)
    else:
        return ''


def _async_attr_mapper(attr_name, val):
    """The `async` attribute works slightly different than the other bool
    attributes. It can be set explicitly to `false` with no surrounding quotes
    according to the spec."""
    if val in [False, 'False']:
        return ' {}=false'.format(attr_name)
    elif val:
        return ' {}'.format(attr_name)
    else:
        return ''


# Allow per-attribute customization of returned string template
SCRIPT_ATTRS = OrderedDict()
SCRIPT_ATTRS['nonce'] = _default_attr_mapper
SCRIPT_ATTRS['id'] = _default_attr_mapper
SCRIPT_ATTRS['src'] = _default_attr_mapper
SCRIPT_ATTRS['type'] = _default_attr_mapper
SCRIPT_ATTRS['async'] = _async_attr_mapper
SCRIPT_ATTRS['defer'] = _bool_attr_mapper
SCRIPT_ATTRS['integrity'] = _default_attr_mapper
SCRIPT_ATTRS['nomodule'] = _bool_attr_mapper

# Generates an interpolatable string of valid attrs eg - '{nonce}{id}...'
ATTR_FORMAT_STR = ''.join(['{{{}}}'.format(a) for a in SCRIPT_ATTRS])


def _unwrap_script(text):
    """Extract content defined between script tags"""
    matches = re.search(r'<script[\s|\S]*>([\s|\S]+?)</script>', text)
    if matches and len(matches.groups()):
        return matches.group(1).strip()

    return text


def build_script_tag(content=None, **kwargs):
    data = {}
    # Iterate all possible script attrs instead of kwargs to make
    # interpolation as easy as possible below
    for attr_name, mapper in SCRIPT_ATTRS.items():
        data[attr_name] = mapper(attr_name, kwargs.get(attr_name))

    # Don't render block contents if the script has a 'src' attribute
    c = _unwrap_script(content) if content and not kwargs.get('src') else ''
    attrs = ATTR_FORMAT_STR.format(**data).rstrip()
    return ('<script{}>{}</script>'.format(attrs, c).strip())


def kwarg_to_directive(kwarg, value=None):
    return setting_to_directive(kwarg, prefix='', value=value)


def csp_definitions_update(csp_definitions, other):
    """ Update one csp defnitions dictionary with another """
    if isinstance(other, dict):
        other = other.items()
    for name, csp in other:
        csp_definitions.setdefault(name, {}).update(csp)
    return csp_definitions
