import warnings

from django.conf import settings

from . import (
    setting_to_directive,
    directive_to_setting,
    DIRECTIVES,
)

CHILD_SRC_DEPRECATION_WARNING = (
    'child-src is deprecated in CSP v3. Use frame-src and worker-src.'
)

LEGACY_SETTINGS_NAMES_DEPRECATION_WARNING = (
    'The following settings are deprecated: %s. '
    'Use CSP_POLICY_DEFINITIONS and CSP_POLICIES instead.'
)


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
