# Sphinx Documentation

## Installation

Sphinx can be installed on CentOS using Yum:

```sh
yum install python-sphinx
```

##

You can also install Sphinx in an Anaconda environment:

```sh
conda install sphinx
```

> Source: https://www.sphinx-doc.org/en/master/usage/installation.html,

## Getting started (the easy way)

1. Create a project directory and move into it:

```sh
mkdir [project_name_here] && cd [project_name_here]
```

##

2. The quickest and easiest way to get started with Sphinx is to use its quickstart command line utitlity. It will ask you a series of questions and set up the source diretory and conf.py file for you.
   **NOTE:** Answer "y" for the first question ("Separate source and build directories"). Answer the rest of the answers how you see fit.

```sh
sphinx-quickstart docs
```

&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;After running the command above, you should see a folder named "docs" in the project's directory.

##

3. Next, install the Sphinx dependency via PIP. **NOTE:** It is recommended that you install this and any other dependencies in a virtual environment (ex: venv, conda):

```sh
pip install sphinx
```

##

4. Check if the command line is available:

```sh
sphinx-build --version
```

> Source: https://www.sphinx-doc.org/en/master/usage/quickstart.html

## Installing the "Read the Docs" theme

We all know the "Read the Docs" theme is the superior theme for documentation. Here's how to use it with Sphinx:

1. Install the theme via PIP

```sh
pip install sphinx_rtd_theme
```

2. Modify the conf.py file in **docs/source**

```py
extensions = [
    ...
    'sphinx_rtd_theme',
]

html_theme = "sphinx_rtd_theme"
```

> Source: https://sphinx-rtd-theme.readthedocs.io/en/stable/installing.html

## Building the docs

1. Move to the project's root directory
2. Run the following command to generate HTML docs:

```sh
sphinx-build -b html docs/source/ docs/build/html
```

3. Open **docs/build/html/index.html** in the browser to view the generated docs

You can generate docs in different formats including PDF, EPUB [and more](https://www.sphinx-doc.org/en/master/usage/builders/index.html#builders). Even more builders can be added via [extensions](https://www.sphinx-doc.org/en/master/usage/extensions/index.html). For example, to build the docs in LaTeX PDF format, run the following command:

```sh
sphinx-build -M latexpdf docs/source/ docs/build/latexpdf
```

## Directives

Directives are generic blocks of explicit markup. Sphinx provides many directives. You can find the extensive list of them [here](https://www.sphinx-doc.org/en/master/usage/restructuredtext/directives.html). Directives are used in .rst files (pages). There are some examples of directive usage in the .rst files provided in this project.

## Creating new pages

Pages need to be created in .rst format. A couple of example pages has been provided in this project (usage.rst, test/testpage.rst).

## index.rst file

This file serves as the root document of the project, serves as the welcome page and contains the root of the table of contents tree (toctree). In this project, I have included an example of referencing a page (usage.rst) in the [toctree directive](https://www.sphinx-doc.org/en/master/usage/restructuredtext/directives.html#directive-toctree).

## reStructuredText (reST)

reST is the default markup language and parser system that Sphinx uses. For the authoritative reStructuredText reference, refer to the documentation [here](https://docutils.sourceforge.io/rst.html).

## autodoc extension

By default Sphinx does not come setup with auto documenting. This is something that has to be configured manually using Sphinx' autodoc extension.

1. Start by adding "sphinx.ext.autodoc" to the list of extensions in the conf.py file

```py
extensions = [
    ...
    "sphinx.ext.autodoc"
]
```

2. Now we have to modify the sys.path in order for autodoc to see our package/project. At the top of the conf.py file, insert the following:
   **NOTE:** This path may be different for your project. Since we put our package outside of the "docs" folder, we need to go up two directories to get to where our package sits (test folder).

```py
import os
import sys

sys.path.insert(0, os.path.abspath('../..'))
```

3. On the page where you want the docs for this module to appear, use the `automodule` directive to have autodoc automatically generate documentation from the code (ex: hello-world.rst):

```rst
.. automodule:: test.main
    :members:
```

> The members directive recursively finds all members of a module. For example, in test.main there are two functions (`print_hello_world()` and `random_number()`), both of which are found by autodocs due to the :members: directive.

> Sources: https://www.sphinx-doc.org/en/master/usage/extensions/autodoc.html#directive-automodule, https://eikonomega.medium.com/getting-started-with-sphinx-autodoc-part-1-2cebbbca5365
