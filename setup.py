from setuptools import setup, find_packages

setup(name='featherduster',
      version='0.2',
      description='An automated cryptanalysis tool',
      url='http://github.com/nccgroup/featherduster',
      author='Daniel "unicornfurnace" Crowley',
      author_email='daniel.crowley@nccgroup.trust',
      license='BSD',
      #packages=['cryptanalib','feathermodules','featherduster'],
      packages=find_packages(exclude=['examples','tests']),
      install_requires=[
          'gmpy',
          'pycrypto',
          'ishell'
      ],
      entry_points = {
         'console_scripts': ['featherduster=featherduster.featherduster:main'],
      },
      zip_safe=False)
