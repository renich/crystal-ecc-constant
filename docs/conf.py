# Configuration file for the Sphinx documentation builder.
# crystal-ecc-constant: Constant-Time Elliptic Curve Cryptography for Crystal

project = 'crystal-ecc-constant'
copyright = '2026, Rénich Bon Ćirić (Copyleft)'
author = 'Rénich Bon Ćirić'
release = '0.2.2'

extensions = [
    'sphinx.ext.autodoc',
    'sphinx.ext.viewcode',
    'sphinx.ext.todo',
]

templates_path = ['_templates']
exclude_patterns = ['_build', 'build', 'technical/api', 'Thumbs.db', '.DS_Store']

html_theme = 'sphinx_rtd_theme'
html_static_path = []
html_title = 'Crystal ECC Constant Documentation'
html_show_sourcelink = False
