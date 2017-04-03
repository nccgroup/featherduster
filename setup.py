from setuptools import setup

setup(name='featherduster',
      version='0.2',
      description='An automated cryptanalysis tool',
      url='http://github.com/nccgroup/featherduster',
      author='Daniel "unicornfurnace" Crowley',
      author_email='daniel.crowley@nccgroup.trust',
      license='BSD',
      packages=['cryptanalib','feathermodules'],
      install_requires=[
          'gmpy',
          'pycrypto',
          'ishell'
      ],
      zip_safe=False)
