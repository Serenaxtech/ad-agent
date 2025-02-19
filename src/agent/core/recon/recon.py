from ldapconnector import ldapConnector
import logging
from types import MethodType
from configreader import configReader

ldaprecon_logger = logging.getLogger(__name__)

class Recon:
    def __init__(self, config_obj, ldapconnector_obj):
        self.config_obj = config_obj
        self.ldapconnector_obj = ldapconnector_obj
        self._dynamically_create_methods()

    def _dynamically_create_methods(self):
        """Create methods dynamically based on queries defined in the config."""
        for section in self.config_obj.sections():
            if not section.startswith('query_'):
                continue  # Skip non-query sections

            method_name = section[len('query_'):]  # Extract method name
            if not self._validate_section(section, method_name):
                continue

            # Retrieve parameters from the config
            ldapfilter = self.config_obj.get(section, 'filter')
            attributes = self._parse_attributes(section)
            scope = self.config_obj.get(section, 'scope', fallback='subtree')
            base = self.config_obj.get(section, 'base')

            # Dynamically create and bind the method
            self._create_dynamic_method(method_name, ldapfilter, attributes, base, scope)

    def _validate_section(self, section, method_name):
        """Ensure the section has a valid filter and method name."""
        if not self.config_obj.has_option(section, 'filter'):
            ldaprecon_logger.warning(f"Section {section} missing 'filter'; skipping.")
            return False
        if not method_name.isidentifier():
            ldaprecon_logger.warning(f"Invalid method name '{method_name}'; skipping.")
            return False
        return True

    def _parse_attributes(self, section):
        """Parse comma-separated attributes or default to '*' (all)."""
        attributes = self.config_obj.get(section, 'attributes', fallback='*')
        return [attr.strip() for attr in attributes.split(',')] if attributes != '*' else None

    def _create_dynamic_method(self, method_name, ldapfilter, attributes, base, scope):
        """Create a method and bind it to the instance."""
        def dynamic_method(self):
            ldaprecon_logger.info(f"Executing query: {method_name}")
            self.ldapconnector_obj.query(
                ldapfilter=ldapfilter,
                attributes=attributes,
                base=base,
                scope=scope
            )

        # Bind the method to the current instance
        bound_method = MethodType(dynamic_method, self)
        setattr(self, method_name, bound_method)