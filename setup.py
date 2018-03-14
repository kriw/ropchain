from setuptools import setup, find_packages
from setuptools.command.install import install
import subprocess
import os
import sys
import shutil

if sys.platform == 'darwin':
    libName = 'ropchain.dylib'
elif sys.platform in ('win32', 'cygwin'):
    libName = 'ropchain.dll'
else:
    libName = 'ropchain.so'

class CustomInstallCommand(install):

    def buildFFI(self):
        libPath = 'ropchain/ffi/build/src/python_module/libropchain*'
        cmd1 = ['cd', 'ropchain/ffi']
        cmd2 = ['waf', 'configure', 'build' '--r2', '--rpp', '--exe', '--mod']
        cmd3 = ['strip', libPath]
        for cmd in (cmd1, cmd2, cmd3):
            subprocess.Popen(cmd).wait()
        shutil.move(libPath, 'ropchain/' + libName)
        shutil.rmtree('ropchain/ffi/')

    def run(self):
        self.buildFFI()
        install.run(self)
 
setup(
        name             = 'ropchain',
        version          = '0.1.5',
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
