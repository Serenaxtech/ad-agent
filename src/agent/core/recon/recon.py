import json
import logging
from types import MethodType
from typing import List, Optional, Iterable, Dict, Any
from ldap.ldap import LdapConnector
from config.config import Config
from ldap3 import SUBTREE, BASE, LEVEL
from logging_custom.logging_custom import configure_logging

recon_logger = logging.getLogger(__name__)

class Recon:
    def __init__(self, config: Config, ldap_connector: LdapConnector):
        self.config = config
        self.ldap = ldap_connector
        self.dynamic_methods = []  # Track successfully created methods
        configure_logging(recon_logger, "recon-module")
        self._create_dynamic_methods()

    def _create_dynamic_methods(self) -> None:
        """Safe dynamic method creation with validation"""
        for section in self.config.get_query_sections():
            method_name = section[len('query_'):]
            
            if not self._is_valid_method_name(method_name):
                continue
                
            try:
                params = self._parse_query_section(section)
                self._bind_dynamic_method(method_name, **params)
            except Exception as e:
                recon_logger.error(f"Failed creating method {method_name}: {str(e)}")

    def _is_valid_method_name(self, name: str) -> bool:
        """Validate method name safety"""
        if not name.isidentifier():
            recon_logger.warning(f"Invalid method name: {name}")
            return False
            
        if hasattr(self, name):
            recon_logger.error(f"Method name conflict: {name}")
            return False
            
        return True

    def _parse_query_section(self, section: str) -> Dict[str, Any]:
        """Safe parameter parsing with validation"""
        params = {
            'ldapfilter': self.config.configFileParser.get(section, 'filter', fallback='(objectClass=*)'),
            'attributes': self._parse_attributes(section),
            'base': self.config.configFileParser.get(section, 'base', fallback=None),
            'scope': self._parse_scope(section),
            'as_json': True
            # 'as_json': self.config.configFileParser.getboolean(section, 'as_json', fallback=True)
        }


        
        if not params['ldapfilter']:
            raise ValueError(f"Missing filter in section {section}")
            
        return params

    def _parse_attributes(self, section: str) -> Optional[List[str]]:
        """Safe attribute list parsing"""
        attrs = self.config.configFileParser.get(section, 'attributes', fallback='*')
        return [a.strip() for a in attrs.split(',')] if attrs != '*' else None

    def _parse_scope(self, section: str) -> int:
        """Convert scope string to LDAP constant"""
        scope_str = self.config.configFileParser.get(section, 'scope', fallback='subtree').lower()
        return Config.SCOPE_MAP.get(scope_str, SUBTREE)

    def _bind_dynamic_method(self, method_name: str, **params) -> None:
        """Create type-annotated dynamic method with error handling"""
        
        def dynamic_method(
            self, 
            override_filter: Optional[str] = None,
            override_attributes: Optional[list] = None,  # Fixed typo here
            override_base: Optional[str] = None,
            override_scope: Optional[str] = None,
            as_json: Optional[bool] = None
        ):
            """Dynamically generated query method"""
            recon_logger.info(f"Executing {method_name}")
            
            try:
                return self.ldap.query(
                    ldapfilter=override_filter or params['ldapfilter'],
                    attributes=override_attributes or params['attributes'],  # Fixed here
                    base=override_base or params['base'],
                    scope=override_scope or params['scope'],
                    as_json=as_json if as_json is not None else params['as_json']
                )
            except Exception as e:
                recon_logger.error(f"Query {method_name} failed: {str(e)}")
                raise

        # Add type annotations dynamically
        dynamic_method.__annotations__ = {
            'override_filter': Optional[str],
            'override_attributes': Optional[list],  # Fixed here
            'override_base': Optional[str],
            'override_scope': Optional[str],
            'as_json': Optional[bool],
            'return': json
        }
        
        # Bind the method once and track it
        setattr(self, method_name, MethodType(dynamic_method, self))
        self.dynamic_methods.append(method_name)  # Track the method name
    

if __name__ == '__main__':
    try:
        # Initialize configuration
        config = Config(config_file='./config.ini')
        # print(config.get_query_sections())
        # print(config.getADDomains())
        
        # Get first domain configuration (for demo purposes)
        domain = config.getADDomains()[0]
        domain_config = config.parseToJson()[domain]

        # Initialize LDAP connection
        ldap_conn = LdapConnector(
            server_string=f"ldap://{domain_config.get('ldap-server', '192.168.8.103')}",
            domain=domain,
            username=domain_config['username'].split('\\')[-1],  # Extract username from DOMAIN\user
            password=domain_config['password'],
            method=domain_config['auth-method']
        )

        # print(ldap_conn.query("(objectClass=Computer)", as_json=True))
        # Initialize Recon module
        recon = Recon(config, ldap_conn)

        # Test dynamic query methods
        print("\n=== Testing Dynamic Methods ===")
        
        # Get list of generated methods

        query_methods = [m for m in dir(recon) 
                    if m.startswith('get_') and callable(getattr(recon, m))]
        
        
        if not query_methods:
            print("No query methods found!")
            exit(1)

        # Execute all found query methods
        for method_name in query_methods:
            print(f"\nExecuting {method_name}():")
            
            try:
                method = getattr(recon, method_name)
                
                # Execute with default parameters
                results = method()
                
                # Convert generator to list for demonstration
                results_list = json.loads(results)
                
                # Print first 3 results as sample
                print(f"First 3 results from {method_name}:")
                for idx, item in enumerate(results_list[:3]):
                    print(f"{idx+1}: {json.dumps(item, indent=2)}")
                    
                # Full results count
                print(f"Total results: {len(results_list)}")
                
                # Test JSON output
                json_results = method(as_json=True)
                print(f"\nJSON output sample (first 100 chars):")
                print(json_results[:100] + "...")
                
            except Exception as e:
                print(f"Error in {method_name}: {str(e)}")
                continue

        # Test error handling
        print("\n=== Testing Error Handling ===")
        try:
            print("Attempting invalid query...")
            invalid_results = recon.get_all_users(override_filter="(invalidFilter)")
            list(invalid_results)  # Force generator execution
        except Exception as e:
            print(f"Properly handled error: {str(e)}")

    except Exception as e:
        logging.error(f"Critical test failure: {str(e)}")
        exit(1)