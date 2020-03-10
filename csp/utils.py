import copy
import re
import warnings

from collections import OrderedDict
from itertools import chain

from django.conf import settings
from django.utils.crypto import get_random_string
from django.utils.encoding import force_str

try:
    from django.utils.six.moves import http_client
except ImportError:
    # django 3.x removed six
    import http.client as http_client

from .conf import (
    defaults, deprecation,
    setting_to_directive, PSEUDO_DIRECTIVES,
)


HTTP_HEADERS = (
    'Content-Security-Policy',
    'Content-Security-Policy-Report-Only',
)


EXEMPTED_DEBUG_CODES = {
    http_client.INTERNAL_SERVER_ERROR,
    http_client.NOT_FOUND,
}


def from_settings():
    policies = getattr(settings, 'CSP_POLICIES', defaults.POLICIES)
    definitions = csp_definitions_update({}, defaults.POLICY_DEFINITIONS)
    custom_definitions = getattr(
        settings,
        'CSP_POLICY_DEFINITIONS',
        {'default': {}},
    )
     # Technically we're modifying Django settings here,
     # but it shouldn't matter since the end result of either will be the same
    deprecation._handle_legacy_settings(custom_definitions)
    for name, csp in custom_definitions.items():
        definitions[name].update(csp)
    # TODO: Error handling
    # TODO: Remove in October 2020 when ordered dicts are the default
    return OrderedDict(
        (name, definitions[name]) for name in policies
    )


def _normalize_config(config, key='default'):
    """
    Permits the config to be a single policy, which will be returned under the
    'default' key by default.
    """
    if config is None:
        return {}
    if not config:
        return config

    if not isinstance(next(iter(config.values())), dict):
        return {'default': config}
    return config


def build_policy(
    config=None,
    update=None,
    replace=None,
    nonce=None,
    order=None,
):
    """
    Builds the policy from the settings as a list of tuples:
    (policy_string<str>, report_only<bool>)
    """
    if config is None:
        config = from_settings()
    else:
        config = _normalize_config(config)
        # Be careful, don't mutate config as it could be from settings
    update = _normalize_config(update)
    replace = _normalize_config(replace)

    policies = OrderedDict()
    for name, policy in config.items():
        new_policy = _replace_policy(policy, replace.get(name, {}))
        update_policy = update.get(name)
        if update_policy is not None:
            _update_policy(new_policy, update_policy)
        policies[name] = new_policy
    _append_policies(policies, update, config)

    if order:  # empty order not permitted: use csp_exempt instead
        policies = (policies[index_or_name] for index_or_name in order)
    else:
        policies = policies.values()

    return [_compile_policy(csp, nonce=nonce) for csp in policies]


def _append_policies(policies, append, config=None):
    if config is None:
        config = {}
    for key, append_csp in append.items():
        if key in policies:
            continue

        if key in config and not append_csp:
            csp = config[key].copy()
        else:
            # TODO: design decision
            append_template = getattr(
                settings,
                'CSP_UPDATE_TEMPLATE',
                defaults.UPDATE_TEMPLATE,
            )
            if append_template is None:
                csp = {}
            elif append_template in config:
                csp = config[append_template]
            else:
                # TODO: Error Handling
                csp = defaults.POLICIES[append_template]
        _update_policy(csp, append_csp)
        policies[key] = csp


def _update_policy(csp, update):
    for k, v in update.items():
        if v is not None:
            if k in PSEUDO_DIRECTIVES:
                csp[k] = v
                continue

            if not isinstance(v, (list, tuple)):
                v = (v,)

            if csp.get(k) is None:
                csp[k] = v
            else:
                csp[k] += tuple(v)


def _replace_policy(csp, replace):
    new_policy = {}
    for k in set(chain(csp, replace)):
        if k in replace:
            v = replace[k]
        else:
            v = csp[k]
        if v is not None:
            if k in PSEUDO_DIRECTIVES:
                new_policy[k] = v
                continue
            v = copy.copy(v)
            if not isinstance(v, (list, tuple)):
                v = (v,)
            new_policy[k] = v
    return new_policy


def _compile_policy(csp, nonce=None):
    report_uri = csp.pop(
        'report-uri',
        defaults.POLICY_DEFINITIONS['default']['report-uri'],
    )
    report_only = csp.pop(
        'report_only',
        defaults.POLICY_DEFINITIONS['default']['report_only'],
    )
    include_nonce_in = csp.pop(
        'include_nonce_in',
        defaults.POLICY_DEFINITIONS['default']['include_nonce_in']
    )

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
            warnings.warn(
                deprecation.CHILD_SRC_DEPRECATION_WARNING,
                DeprecationWarning,
            )

    if report_uri:
        report_uri = map(force_str, report_uri)
        policy_parts['report-uri'] = ' '.join(report_uri)

    if nonce:
        for section in include_nonce_in:
            policy = policy_parts.get(section, '')
            policy_parts[section] = ("%s %s" %
                                     (policy, "'nonce-%s'" % nonce)).strip()

    policy_string = '; '.join(
        '{} {}'.format(k, val).strip() for k, val in policy_parts.items()
    )

    return policy_string, report_only


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


def _clean_input_policy(policy):
    return dict(
        kwarg_to_directive(in_directive, value=value)
        for in_directive, value in policy.items()
    )


def csp_definitions_update(csp_definitions, other):
    """ Update one csp defnitions dictionary with another """
    if isinstance(other, dict):
        other = other.items()
    for name, csp in other:
        csp_definitions.setdefault(name, {}).update(csp)
    return csp_definitions


class PolicyNames:
    length = 20
    last_policy_name = None

    def __next__(self):
        self.last_policy_name = get_random_string(self.length)
        return self.last_policy_name

    def __iter__(self):
        return self
policy_names = PolicyNames()


def iter_policies(policies):
    """
    Accepts the following formats:
    - a policy dictionary (formatted like in settings.CSP_POLICY_DEFINITIONS)
    - an iterable of policies: (item, item, item,...)

    item can be any of the following:
        - string representing a named policy in settings.CSP_POLICY_DEFINITIONS
        - subscriptable two-tuple: (name, csp)
        - csp dictionary which will be assigned a random name

    Yields a tuple: (name, csp)
    """
    if isinstance(policies, dict):
        yield from (
            (name, _clean_input_policy(policy))
            for name, policy in policies.items()
        )
        return

    for policy in policies:
        if isinstance(policy, str):
            # Named policies will be handled by the middleware
            yield (policy, {})
        elif isinstance(policy, (list, tuple)):
            yield (policy[0], _clean_input_policy(policy[1]))
        else:  # dictionary containing a single csp
            yield (next(policy_names), _clean_input_policy(policy))


def _policies_from_names_and_kwargs(
    csp_names=('default',),
    csp_definitions=None,
    **kwargs,
):
    """
    Helper used in csp_update and csp_replace to process args
    """
    if csp_definitions:
        csp_definitions = csp_definitions_update(kwargs, csp_definitions)

    if csp_names is None:
        update = csp_definitions

    if not kwargs:
        update = OrderedDict(
            # We don't need to fetch the config
            # since the append logic handles this
            (name, None) for name in update
        )
    else:
        # Legacy behaviour + bulk update support
        update = OrderedDict(iter_policies(
            (csp_name, kwargs) for csp_name in csp_names
        ))
    return update
