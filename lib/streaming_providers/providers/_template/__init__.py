# providers/_template/__init__.py
"""
Template scaffold -- not a real provider.

This directory is a copy source for new providers, not a registrable
plugin. Its module does not import or export any StreamingProvider
subclass, so directory-based discovery (see streaming_providers/__init__.py)
never registers it, even if the leading-underscore skip rule is removed.

To use: copy this directory to providers/{new_name}/ and rename the
classes. Then replace the body of this __init__.py with:

    from .provider import YourProvider   # renamed

    __all__ = ["YourProvider"]

The registry derives the plugin name from the class name
(`cls.__name__.lower().replace("provider", "")`), so the class name must
match the directory name you chose.
"""

__all__ = []