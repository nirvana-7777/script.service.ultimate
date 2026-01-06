# streaming_providers/base/settings/models/settings_models.py
import ipaddress
import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Dict, List, Optional, Union
from urllib.parse import urlparse


class SettingType(Enum):
    """Supported setting value types"""

    STRING = "string"
    INTEGER = "integer"
    BOOLEAN = "boolean"
    FLOAT = "float"
    SELECT = "select"  # dropdown with predefined options
    PASSWORD = "password"  # masked string input
    URL = "url"  # URL with validation
    IP_ADDRESS = "ip_address"  # IP address validation
    PORT = "port"  # Port number (1-65535)
    EMAIL = "email"  # Email address validation


@dataclass
class ValidationRule:
    """Validation rule for a setting value"""

    name: str
    validator: Callable[[Any], bool]
    error_message: str

    def validate(self, value: Any) -> bool:
        """Validate a setting value against this rule"""
        try:
            return self.validator(value)
        except Exception:
            return False

    def get_error_message(self) -> str:
        """Get human-readable error message for validation failure"""
        return self.error_message


class StandardValidationRules:
    """Standard validation rules for common use cases"""

    @staticmethod
    def not_empty(error_msg: str = "Value cannot be empty") -> ValidationRule:
        """Rule to ensure value is not empty"""
        return ValidationRule(
            name="not_empty",
            validator=lambda x: x is not None and str(x).strip() != "",
            error_message=error_msg,
        )

    @staticmethod
    def min_length(min_len: int, error_msg: Optional[str] = None) -> ValidationRule:
        """Rule to ensure string has minimum length"""
        if error_msg is None:
            error_msg = f"Value must be at least {min_len} characters long"
        return ValidationRule(
            name="min_length",
            validator=lambda x: isinstance(x, str) and len(x) >= min_len,
            error_message=error_msg,
        )

    @staticmethod
    def max_length(max_len: int, error_msg: Optional[str] = None) -> ValidationRule:
        """Rule to ensure string has maximum length"""
        if error_msg is None:
            error_msg = f"Value must be at most {max_len} characters long"
        return ValidationRule(
            name="max_length",
            validator=lambda x: isinstance(x, str) and len(x) <= max_len,
            error_message=error_msg,
        )

    @staticmethod
    def numeric_range(
        min_val: Union[int, float],
        max_val: Union[int, float],
        error_msg: Optional[str] = None,
    ) -> ValidationRule:
        """Rule to ensure numeric value is within range"""
        if error_msg is None:
            error_msg = f"Value must be between {min_val} and {max_val}"
        return ValidationRule(
            name="numeric_range",
            validator=lambda x: isinstance(x, (int, float)) and min_val <= x <= max_val,
            error_message=error_msg,
        )

    @staticmethod
    def regex_pattern(pattern: str, error_msg: str) -> ValidationRule:
        """Rule to validate against regex pattern"""
        compiled_pattern = re.compile(pattern)
        return ValidationRule(
            name="regex_pattern",
            validator=lambda x: isinstance(x, str) and bool(compiled_pattern.match(x)),
            error_message=error_msg,
        )

    @staticmethod
    def valid_email(error_msg: str = "Invalid email address format") -> ValidationRule:
        """Rule to validate email address"""
        email_pattern = r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$"
        return StandardValidationRules.regex_pattern(email_pattern, error_msg)

    @staticmethod
    def valid_url(error_msg: str = "Invalid URL format") -> ValidationRule:
        """Rule to validate URL format"""

        def validate_url(value: str) -> bool:
            if not isinstance(value, str):
                return False
            try:
                result = urlparse(value)
                return all([result.scheme, result.netloc])
            except Exception:
                return False

        return ValidationRule(
            name="valid_url", validator=validate_url, error_message=error_msg
        )

    @staticmethod
    def valid_ip_address(
        error_msg: str = "Invalid IP address format",
    ) -> ValidationRule:
        """Rule to validate IP address (IPv4 or IPv6)"""

        def validate_ip(value: str) -> bool:
            if not isinstance(value, str):
                return False
            try:
                ipaddress.ip_address(value)
                return True
            except ValueError:
                return False

        return ValidationRule(
            name="valid_ip_address", validator=validate_ip, error_message=error_msg
        )

    @staticmethod
    def valid_port(
        error_msg: str = "Port must be between 1 and 65535",
    ) -> ValidationRule:
        """Rule to validate port number"""
        return ValidationRule(
            name="valid_port",
            validator=lambda x: isinstance(x, int) and 1 <= x <= 65535,
            error_message=error_msg,
        )

    @staticmethod
    def in_choices(
        choices: List[Any], error_msg: Optional[str] = None
    ) -> ValidationRule:
        """Rule to ensure value is in predefined choices"""
        if error_msg is None:
            error_msg = f"Value must be one of: {', '.join(map(str, choices))}"
        return ValidationRule(
            name="in_choices", validator=lambda x: x in choices, error_message=error_msg
        )


@dataclass
class SettingValue:
    """Container for a setting value with metadata and validation"""

    setting_type: SettingType
    default_value: Any = None
    current_value: Any = None
    choices: Optional[List[Any]] = None  # For SELECT type
    validation_rules: List[ValidationRule] = field(default_factory=list)
    description: Optional[str] = None
    display_name: Optional[str] = None
    is_sensitive: bool = False  # For passwords, secrets, etc.
    kodi_setting_id: Optional[str] = None  # Mapping to Kodi setting ID

    def __post_init__(self):
        """Post-initialization setup"""
        # Set current value to default if not provided
        if self.current_value is None:
            self.current_value = self.default_value

        # Add type-specific validation rules
        self._add_type_validation()

        # Add choices validation for SELECT type
        if self.setting_type == SettingType.SELECT and self.choices:
            self.add_validation_rule(StandardValidationRules.in_choices(self.choices))

    def is_required(self) -> bool:
        """Check if this setting is required (has not_empty validation rule)"""
        return any(rule.name == "not_empty" for rule in self.validation_rules)

    def _add_type_validation(self):
        """Add validation rules based on setting type"""
        if self.setting_type == SettingType.INTEGER:
            self.add_validation_rule(
                ValidationRule(
                    name="is_integer",
                    validator=lambda x: isinstance(x, int)
                    or (isinstance(x, str) and x.isdigit()),
                    error_message="Value must be an integer",
                )
            )

        elif self.setting_type == SettingType.FLOAT:
            self.add_validation_rule(
                ValidationRule(
                    name="is_float",
                    validator=lambda x: isinstance(x, (int, float))
                    or self._is_valid_float_string(x),
                    error_message="Value must be a number",
                )
            )

        elif self.setting_type == SettingType.BOOLEAN:
            self.add_validation_rule(
                ValidationRule(
                    name="is_boolean",
                    validator=lambda x: isinstance(x, bool)
                    or str(x).lower() in ["true", "false", "1", "0"],
                    error_message="Value must be true or false",
                )
            )

        elif self.setting_type == SettingType.URL:
            self.add_validation_rule(StandardValidationRules.valid_url())

        elif self.setting_type == SettingType.IP_ADDRESS:
            self.add_validation_rule(StandardValidationRules.valid_ip_address())

        elif self.setting_type == SettingType.PORT:
            self.add_validation_rule(StandardValidationRules.valid_port())

        elif self.setting_type == SettingType.EMAIL:
            self.add_validation_rule(StandardValidationRules.valid_email())

    def _is_valid_float_string(self, value: Any) -> bool:
        """Check if string can be converted to float"""
        if not isinstance(value, str):
            return False
        try:
            float(value)
            return True
        except ValueError:
            return False

    def set_value(self, value: Any) -> bool:
        """
        Set the setting value with validation and type conversion

        Args:
            value: New value to set

        Returns:
            True if value was set successfully, False if validation failed
        """
        # Convert value to appropriate type
        converted_value = self._convert_value(value)
        if converted_value is None:
            return False

        # Validate the converted value
        if not self._validate_value(converted_value):
            return False

        self.current_value = converted_value
        return True

    def _convert_value(self, value: Any) -> Any:
        """Convert value to the appropriate type"""
        if value is None:
            return None

        try:
            if (
                self.setting_type == SettingType.STRING
                or self.setting_type == SettingType.PASSWORD
            ):
                return str(value)

            elif (
                self.setting_type == SettingType.INTEGER
                or self.setting_type == SettingType.PORT
            ):
                if isinstance(value, int):
                    return value
                elif isinstance(value, str) and value.isdigit():
                    return int(value)
                else:
                    return None

            elif self.setting_type == SettingType.FLOAT:
                if isinstance(value, (int, float)):
                    return float(value)
                elif isinstance(value, str):
                    return float(value)
                else:
                    return None

            elif self.setting_type == SettingType.BOOLEAN:
                if isinstance(value, bool):
                    return value
                elif isinstance(value, str):
                    return value.lower() in ["true", "1", "yes", "on"]
                elif isinstance(value, int):
                    return bool(value)
                else:
                    return None

            elif self.setting_type in [
                SettingType.SELECT,
                SettingType.URL,
                SettingType.IP_ADDRESS,
                SettingType.EMAIL,
            ]:
                return str(value)

            else:
                return value

        except (ValueError, TypeError):
            return None

    def _validate_value(self, value: Any) -> bool:
        """Validate value against all validation rules"""
        for rule in self.validation_rules:
            if not rule.validate(value):
                return False
        return True

    def get_value(self) -> Any:
        """Get the current setting value"""
        return self.current_value

    def get_display_value(self) -> str:
        """Get value formatted for display (masks sensitive values)"""
        if self.is_sensitive and self.current_value:
            return "*" * min(len(str(self.current_value)), 8)
        return str(self.current_value) if self.current_value is not None else ""

    def add_validation_rule(self, rule: ValidationRule) -> None:
        """Add a validation rule to this setting"""
        # Check if rule with same name already exists
        existing_names = {r.name for r in self.validation_rules}
        if rule.name not in existing_names:
            self.validation_rules.append(rule)

    def remove_validation_rule(self, rule_name: str) -> bool:
        """Remove a validation rule by name"""
        original_length = len(self.validation_rules)
        self.validation_rules = [
            r for r in self.validation_rules if r.name != rule_name
        ]
        return len(self.validation_rules) < original_length

    def validate(self) -> tuple[bool, List[str]]:
        """
        Validate current value against all rules

        Returns:
            Tuple of (is_valid, list_of_error_messages)
        """
        if self.current_value is None:
            # Check if this setting is required (has not_empty rule)
            has_required_rule = any(
                rule.name == "not_empty" for rule in self.validation_rules
            )
            if has_required_rule:
                return False, ["Value is required"]
            else:
                return True, []

        errors = []
        for rule in self.validation_rules:
            if not rule.validate(self.current_value):
                errors.append(rule.get_error_message())

        return len(errors) == 0, errors

    def reset_to_default(self) -> None:
        """Reset value to default"""
        self.current_value = self.default_value

    def has_value(self) -> bool:
        """Check if setting has a non-None value"""
        return self.current_value is not None

    def is_modified(self) -> bool:
        """Check if current value differs from default"""
        return self.current_value != self.default_value

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary representation"""
        is_valid, errors = self.validate()

        return {
            "setting_type": self.setting_type.value,
            "current_value": self.current_value,
            "default_value": self.default_value,
            "choices": self.choices,
            "description": self.description,
            "display_name": self.display_name,
            "is_sensitive": self.is_sensitive,
            "kodi_setting_id": self.kodi_setting_id,
            "is_valid": is_valid,
            "validation_errors": errors,
            "has_value": self.has_value(),
            "is_modified": self.is_modified(),
            "display_value": self.get_display_value(),
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "SettingValue":
        """Create SettingValue from dictionary representation"""
        setting = cls(
            setting_type=SettingType(data["setting_type"]),
            default_value=data.get("default_value"),
            current_value=data.get("current_value"),
            choices=data.get("choices"),
            description=data.get("description"),
            display_name=data.get("display_name"),
            is_sensitive=data.get("is_sensitive", False),
            kodi_setting_id=data.get("kodi_setting_id"),
        )
        return setting

    def clone(self) -> "SettingValue":
        """Create a copy of this setting"""
        return SettingValue(
            setting_type=self.setting_type,
            default_value=self.default_value,
            current_value=self.current_value,
            choices=self.choices.copy() if self.choices else None,
            validation_rules=self.validation_rules.copy(),
            description=self.description,
            display_name=self.display_name,
            is_sensitive=self.is_sensitive,
            kodi_setting_id=self.kodi_setting_id,
        )


class SettingValueBuilder:
    """Builder pattern for creating SettingValue instances"""

    def __init__(self, setting_type: SettingType):
        self._setting_type = setting_type
        self._default_value = None
        self._choices = None
        self._validation_rules = []
        self._description = None
        self._display_name = None
        self._is_sensitive = False
        self._kodi_setting_id = None

    def default(self, value: Any) -> "SettingValueBuilder":
        """Set default value"""
        self._default_value = value
        return self

    def choices(self, choices: List[Any]) -> "SettingValueBuilder":
        """Set choices for SELECT type"""
        self._choices = choices
        return self

    def description(self, desc: str) -> "SettingValueBuilder":
        """Set description"""
        self._description = desc
        return self

    def display_name(self, name: str) -> "SettingValueBuilder":
        """Set display name"""
        self._display_name = name
        return self

    def sensitive(self, is_sensitive: bool = True) -> "SettingValueBuilder":
        """Mark as sensitive (for passwords, etc.)"""
        self._is_sensitive = is_sensitive
        return self

    def kodi_setting(self, setting_id: str) -> "SettingValueBuilder":
        """Set Kodi setting ID mapping"""
        self._kodi_setting_id = setting_id
        return self

    def required(self) -> "SettingValueBuilder":
        """Mark as required (not empty)"""
        self._validation_rules.append(StandardValidationRules.not_empty())
        return self

    def min_length(self, length: int) -> "SettingValueBuilder":
        """Add minimum length validation"""
        self._validation_rules.append(StandardValidationRules.min_length(length))
        return self

    def max_length(self, length: int) -> "SettingValueBuilder":
        """Add maximum length validation"""
        self._validation_rules.append(StandardValidationRules.max_length(length))
        return self

    def numeric_range(
        self, min_val: Union[int, float], max_val: Union[int, float]
    ) -> "SettingValueBuilder":
        """Add numeric range validation"""
        self._validation_rules.append(
            StandardValidationRules.numeric_range(min_val, max_val)
        )
        return self

    def custom_validation(self, rule: ValidationRule) -> "SettingValueBuilder":
        """Add custom validation rule"""
        self._validation_rules.append(rule)
        return self

    def build(self) -> SettingValue:
        """Build the SettingValue instance"""
        setting = SettingValue(
            setting_type=self._setting_type,
            default_value=self._default_value,
            choices=self._choices,
            description=self._description,
            display_name=self._display_name,
            is_sensitive=self._is_sensitive,
            kodi_setting_id=self._kodi_setting_id,
        )

        # Add custom validation rules
        for rule in self._validation_rules:
            setting.add_validation_rule(rule)

        return setting


# Convenience factory functions
def string_setting(default: str = "", required: bool = False) -> SettingValueBuilder:
    """Create a string setting builder"""
    builder = SettingValueBuilder(SettingType.STRING).default(default)
    if required:
        builder.required()
    return builder


def password_setting(required: bool = True) -> SettingValueBuilder:
    """Create a password setting builder"""
    builder = SettingValueBuilder(SettingType.PASSWORD).sensitive(True)
    if required:
        builder.required()
    return builder


def integer_setting(
    default: int = 0, min_val: Optional[int] = None, max_val: Optional[int] = None
) -> SettingValueBuilder:
    """Create an integer setting builder"""
    builder = SettingValueBuilder(SettingType.INTEGER).default(default)
    if min_val is not None and max_val is not None:
        builder.numeric_range(min_val, max_val)
    return builder


def boolean_setting(default: bool = False) -> SettingValueBuilder:
    """Create a boolean setting builder"""
    return SettingValueBuilder(SettingType.BOOLEAN).default(default)


def select_setting(choices: List[Any], default: Any = None) -> SettingValueBuilder:
    """Create a select setting builder"""
    builder = SettingValueBuilder(SettingType.SELECT).choices(choices)
    if default is not None:
        builder.default(default)
    return builder


def url_setting(required: bool = False) -> SettingValueBuilder:
    """Create a URL setting builder"""
    builder = SettingValueBuilder(SettingType.URL)
    if required:
        builder.required()
    return builder


def port_setting(default: int = 8080) -> SettingValueBuilder:
    """Create a port setting builder"""
    return SettingValueBuilder(SettingType.PORT).default(default)


def ip_setting(required: bool = False) -> SettingValueBuilder:
    """Create an IP address setting builder"""
    builder = SettingValueBuilder(SettingType.IP_ADDRESS)
    if required:
        builder.required()
    return builder
