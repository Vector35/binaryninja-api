
#
# to build the distribution file:
#    python setup.py sdist  --formats=gztar,zip
#
# to build an installer for windows:
#    python setup.py bdist_wininst
#
# to install the distribution file:
#     python setup.py install

from distutils.core import setup
setup(name='mbuild',
      version='0.2496',
      url='https://github.com/intelxed/mbuild',
      description='mbuild: python based build system',
      author='XED Team',
      author_email='xed.team@intel.com',
      packages=['mbuild']
      )

