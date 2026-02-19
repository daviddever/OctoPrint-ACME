from setuptools import setup

plugin_identifier = "acme"
plugin_package = "octoprint_acme"
plugin_name = "OctoPrint-ACME"
plugin_version = "0.1.0"
plugin_description = (
    "Let's Encrypt SSL certificate management for OctoPi "
    "via lego and Cloudflare DNS-01"
)
plugin_author = "David Dever"
plugin_author_email = ""
plugin_url = "https://github.com/daviddever/OctoPrint-ACME"
plugin_license = "AGPLv3"
plugin_requires = ["cryptography>=3.0"]
plugin_additional_data = []
plugin_additional_packages = []
plugin_ignored_packages = []
additional_setup_parameters = {}

try:
    import octoprint_setuptools
except ImportError:
    print(
        "Could not import OctoPrint's setuptools, "
        "are you sure you are running that within OctoPrint's venv?"
    )
    import sys

    sys.exit(-1)

setup_parameters = octoprint_setuptools.create_plugin_setup_parameters(
    identifier=plugin_identifier,
    package=plugin_package,
    name=plugin_name,
    version=plugin_version,
    description=plugin_description,
    author=plugin_author,
    mail=plugin_author_email,
    url=plugin_url,
    license=plugin_license,
    requires=plugin_requires,
    additional_data=plugin_additional_data,
    additional_packages=plugin_additional_packages,
    ignored_packages=plugin_ignored_packages,
)
setup_parameters.update(additional_setup_parameters)
setup(**setup_parameters)
