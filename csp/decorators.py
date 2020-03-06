from collections import OrderedDict
from functools import wraps
from itertools import chain

from .utils import (
    iter_policies,
    policy_names,
)


def csp_exempt(f):
    @wraps(f)
    def _wrapped(*a, **kw):
        r = f(*a, **kw)
        r._csp_exempt = True
        return r
    return _wrapped


def csp_update(**kwargs):
    update = dict((k.lower().replace('_', '-'), v) for k, v in kwargs.items())

    def decorator(f):
        @wraps(f)
        def _wrapped(*a, **kw):
            r = f(*a, **kw)
            r._csp_update = update
            return r
        return _wrapped
    return decorator


def csp_replace(**kwargs):
    replace = dict((k.lower().replace('_', '-'), v) for k, v in kwargs.items())

    def decorator(f):
        @wraps(f)
        def _wrapped(*a, **kw):
            r = f(*a, **kw)
            r._csp_replace = replace
            return r
        return _wrapped
    return decorator


def csp(policies=(), policy_definitions=None, **kwargs):
    policies = iter_policies(tuple(policies))

    if kwargs and not isinstance(next(iter(kwargs.values())), dict):
        # Single-policy kwargs is the legacy behaviour (deprecate?)
        # TODO: single-policy format isn't currently supported for policy_dict

        policy_name = next(policy_names)
        if policy_definitions:
            policy_definitions[policy_name] = kwargs
        else:
            policy_definitions = [(policy_name, kwargs)]
    elif policy_definitions:
        duplicates = set(kwargs) & set(policy_definitions)
        if duplicates:
            raise TypeError(  # TypeError because python does it
                "csp decorator got multiple policy definitions "
                "for the same name: %s" % ', '.join(duplicates)
            )
        policy_definitions.update(kwargs)
    else:
        policy_definitions = kwargs

    config = OrderedDict(chain(
        iter_policies(policy_definitions),
        policies,
    ))

    def decorator(f):
        @wraps(f)
        def _wrapped(*a, **kw):
            r = f(*a, **kw)
            r._csp_config = config
            return r
        return _wrapped
    return decorator
