from . import defaults

DIRECTIVES = set(defaults.POLICY_DEFINITIONS['default'])
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
