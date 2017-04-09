# Installation
~~~
sudo apt-get install libgmp3-dev # debian/ubuntu specific, your os may have a differently named libGMP package
git clone https://github.com/nccgroup/featherduster.git
cd featherduster
python setup.py install
~~~

# pip/virtualenv
FeatherDuster is pip installable. This means you can simply git clone and pip install like so: 
```bash
$ git clone https://github.com/nccgroup/featherduster.git
$ cd featherduster
$ pip install .
```

Note: You likely want to install into a [python virtual environment](http://python-guide-pt-br.readthedocs.io/en/latest/dev/virtualenvs/).

#### Dependencies
~~~
Python 2.x
GMPy (which itself depends on GMP)
PyCrypto
ishell (which itself depends on readline and ncurses)
~~~

### Installation errors

#### Missing GMP
If you encounter a missing header error such as:
```
./src/gmpy.h:30:10: fatal error: 'gmp.h' file not found
```

##### OSX
Install gmp via brew `brew install gmp` then retry `python setup.py install`

##### Debian
Install gmp via apt-get `sudo apt-get install libgmp3-dev`

#### Missing GCC
If you're having trouble installing PyCrypto on an Ubuntu variant, you may not have gcc installed. It's possible to install PyCrypto through apt with `apt-get install python-crypto`.

#### Missing libncurses
If you encounter an error such as:
```
/usr/bin/ld: cannot find -lncurses
collect2: error: ld returned 1 exit status
error: Setup script exited with error: command 'x86_64-linux-gnu-gcc' failed with exit status 1
```

##### Ubuntu
Install libncurses with `sudo apt-get install libncurses-dev`.
