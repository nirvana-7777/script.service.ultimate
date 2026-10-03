# providers/_template/__init__.py
"""
Template scaffold -- not a real provider.

This directory is a copy source for new providers, not a registrable
plugin. Its module does not import or export any StreamingProvider
subclass, so directory-based discovery (see streaming_providers/__init__.py)
never registers it, even if the leading-underscore skip rule is removed.

To use: copy this directory to providers/{new_name}/ and rename the
classes. Change this __init__.py to import and export YourProvider once
the new provider is a real one.
"""

__all__ = []