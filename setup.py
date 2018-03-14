from setuptools import setup, find_packages
from setuptools.command.install import install
import subprocess
import os
import sys
import shutil
import multiprocessing

if sys.platform == 'darwin':
    libName = 'ropchain.dylib'
elif sys.platform in ('win32', 'cygwin'):
    libName = 'ropchain.dll'
else:
    libName = 'ropchain.so'

class CustomInstallCommand(install):

    def buildFFI(self):
        os.chdir('ropchain/ffi')
        libPath = 'build/src/python_module/lib%s' % libName
        cores = multiprocessing.cpu_count()
        cmd1 = ['pwd']
        cmd2 = ['./waf', 'configure', 'build', '-j%d' % (2 * cores), '--r2', '--rpp', '--exe', '--mod']
        cmd3 = ['strip', libPath]
        for cmd in (cmd1, cmd2, cmd3):
            subprocess.Popen(cmd).wait()
        os.chdir('../..')
        shutil.move('ropchain/ffi/%s' % libPath, 'ropchain/%s' % libName)
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
