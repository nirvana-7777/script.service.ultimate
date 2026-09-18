"""Provider static-metadata mixin: labels, logos, auth-type lists, country handling.

Split out of provider.py. Reads its data from the ClassVar attributes
(PROVIDER_LABEL, SUPPORTED_AUTH_TYPES, PROVIDER_LOGO, SUPPORTED_COUNTRIES)
that remain declared directly on StreamingProvider, since those describe the
concrete provider class itself, not any one capability area.
"""

from typing import TYPE_CHECKING, Any, Dict, List


class ProviderMetadataMixin:
    if TYPE_CHECKING:
        # Provided by StreamingProvider.__init__ once this is composed
        # into the full class — declared here only for type checkers.
        country: str

    @classmethod
    def get_static_label(cls, country: str = None) -> str:
        """
        Get provider label without instantiation.

        Args:
            country: Optional country code for country-specific labels

        Returns:
            Provider label string
        """
        base_label = cls.PROVIDER_LABEL or cls.__name__.replace("Provider", "")

        if country:
            # Format country code
            country_upper = country.upper()

            # Special handling for common cases
            if country_upper == "DE":
                return f"{base_label} Germany"
            elif country_upper == "AT":
                return f"{base_label} Austria"
            elif country_upper == "CH":
                return f"{base_label} Switzerland"
            else:
                return f"{base_label} ({country_upper})"

        return base_label

    @classmethod
    def get_static_auth_types(cls) -> List[str]:
        """
        Get supported authentication types without instantiation.

        Returns:
            List of supported auth type strings
        """
        return cls.SUPPORTED_AUTH_TYPES.copy()

    @classmethod
    def get_static_logo(cls, country: str = None) -> str:
        """
        Get provider logo URL without instantiation.

        Args:
            country: Optional country code for country-specific logos

        Returns:
            Logo URL string
        """
        return cls.PROVIDER_LOGO

    @classmethod
    def get_static_supported_countries(cls) -> List[str]:
        """
        Get supported countries without instantiation.

        Returns:
            List of ISO country codes
        """
        return cls.SUPPORTED_COUNTRIES.copy()

    @classmethod
    def get_all_possible_instances(cls) -> List[Dict[str, Any]]:
        """
        Get metadata for all possible instances of this provider.

        Returns:
            List of instance metadata dictionaries
        """
        instances = []

        if cls.supports_multiple_countries():
            for country in cls.SUPPORTED_COUNTRIES:
                instances.append(
                    {
                        "plugin": cls.__name__.lower().replace("provider", ""),
                        "country": country.upper(),
                        "label": cls.get_static_label(country),
                        "requires_country_suffix": True,
                    }
                )
        else:
            # Single-country provider
            instances.append(
                {
                    "plugin": cls.__name__.lower().replace("provider", ""),
                    "country": "DE",  # Default country for single-country providers
                    "label": cls.get_static_label(),
                    "requires_country_suffix": False,
                }
            )

        return instances

    @property
    def provider_label(self) -> str:
        """Return the provider label (e.g., 'JOYN', 'ZDF', 'RTL+')"""
        # Use static method with instance's country
        return self.get_static_label(self.country)

    @property
    def provider_logo(self) -> str:
        """Return the provider logo URL"""
        return self.get_static_logo()

    @property
    def supported_auth_types(self) -> List[str]:
        """List of authentication types this provider supports."""
        return self.get_static_auth_types()

    @property
    def uses_dynamic_manifests(self) -> bool:
        """Return True if provider uses truly dynamic manifests"""
        return False

    @classmethod
    def get_supported_countries(cls) -> List[str]:
        """
        Get list of countries supported by this provider.

        Returns:
            List of ISO country codes (e.g., ['de', 'at', 'ch'])
            Empty list means single-country provider using default country
        """
        return cls.SUPPORTED_COUNTRIES.copy()

    @classmethod
    def supports_multiple_countries(cls) -> bool:
        """
        Check if this provider supports multiple countries.

        Returns:
            True if provider supports country-specific instances
        """
        return len(cls.SUPPORTED_COUNTRIES) > 1

    @classmethod
    def validate_country(cls, country: str) -> bool:
        """
        Validate if a country is supported by this provider.

        Args:
            country: ISO country code to validate

        Returns:
            True if country is supported or provider is single-country
        """
        if not cls.supports_multiple_countries():
            # Single-country providers accept any country (or ignore it)
            return True

        return country.lower() in [c.lower() for c in cls.SUPPORTED_COUNTRIES]