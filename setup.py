from setuptools import setup, find_packages
 
setup(
        name             = 'ropchain',
        version          = '0.0.1',
        description      = 'ROPChain generator',
        license          = 'GPL3.0',
        author           = 'kriw',
        author_email     = 'kotarou777775@gmail.com',
        url              = 'https://github.com/kriw/ropchain',
        keywords         = '',
        packages         = find_packages(),
        script           = ['require.sh'],
        install_requires = [],
        )
