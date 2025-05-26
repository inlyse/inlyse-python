# -*- coding: utf-8 -*-
from __future__ import unicode_literals

# Standard Library
import os
import sys

PATH = os.path.normpath(os.path.join(os.path.dirname(__file__), "../src"))
sys.path.insert(0, PATH)

extensions = [
    "sphinx.ext.autodoc",
    "sphinx.ext.autosummary",
    "sphinx.ext.coverage",
    "sphinx.ext.doctest",
    "myst_parser",
    "sphinx_toolbox.installation",
    "sphinx_toolbox.github",
    "sphinx.ext.extlinks",
    "sphinx.ext.napoleon",
    "sphinx.ext.viewcode",
    "sphinx_click.ext",
]

if os.getenv("SPELLCHECK"):
    extensions += ("sphinxcontrib.spelling",)
    spelling_show_suggestions = True
    spelling_lang = "en_US"

github_username = "inlyse"
github_repository = "inlyse-python"

source_suffix = {".rst": "restructuredtext", ".md": "markdown"}
master_doc = "index"
project = "inlyse-python"
copyright = "2023, inlyse GmbH"
author = "inlyse GmbH"
version = release = "1.0.2"  # semantic-release

autosummary_generate = True

extlinks = {
    "bb": ("https://github.com/inlyse/inlyse-python", None),
    "issue": ("https://github.com/inlyse/inlyse-python/issues/%s", "#"),
    "pr": ("https://github.com/inlyse/inlyse-python/pull-requests/%s", "PR #"),
}

templates_path = ["_templates"]
exclude_patterns = ["_build", "build"]

add_function_parentheses = True
add_module_names = True

pygments_style = "sphinx"
autodoc_typehints = "none"

html_theme = "nature"
html_logo = "images/inlyse-sidebar-logo.png"
html_display_version = True
html_favicon = "_static/inlyse.ico"
html_use_index = True
html_show_sourcelink = True
html_sourcelink_suffix = ".rst"
html_show_sphinx = False
html_show_copyright = True
html_use_opensearch = ""
html_file_suffix = None
html_static_path = ["_static"]
html_css_files = ["custom.css"]
html_last_updated_fmt = "%b %d, %Y"
html_split_index = False
html_short_title = "%s-%s" % (project, version)
rst_epilog = """
.. _INLYSE API: https://documentation.inlyse.cloud
.. _INLYSE Dashboard: https://dashboard.inlyse.cloud
.. _INLYSE: https://www.inlyse.com
"""
