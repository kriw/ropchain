from setuptools import setup, find_packages
from setuptools.command.install import install
from subprocess import call
import os
import sys

class CustomInstallCommand(install):
    def run(self):
        currentModule = sys.modules[__name__]
        dirName = os.path.dirname(os.path.abspath(currentModule.__file__))
        scriptPath = "%s/require.sh" % dirName
        call(['bash', scriptPath])
        install.run(self)
 
setup(
        name             = 'ropchain',
        version          = '0.1.4',
        description      = 'ROPChain generator',
        license          = 'GPL3.0',
        author           = 'kriw',
        author_email     = 'kotarou777775@gmail.com',
        url              = 'https://github.com/kriw/ropchain',
        keywords         = '',
        packages         = find_packages(),
        cmdclass         = {'install': CustomInstallCommand},
        include_package_data = True
        )
