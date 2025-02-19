from setuptools import setup, find_packages

setup(
    name="ldapconnector",
    version="0.1",
    packages=find_packages(),
    description="An ldap custom package",
    author="Example",
    install_requires=["ldap3"],
)