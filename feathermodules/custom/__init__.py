import os
import sys

path_to_featherduster = os.path.dirname(sys.argv[0])
if path_to_featherduster == '':
   path_to_featherduster = os.getcwd()
path_to_custom_dir = path_to_featherduster + '/feathermodules/custom/'

def py_and_not_init(filename):
   return (filename[-3:] == '.py' and filename != '__init__.py')

__all__ = map(lambda x: x[:-3], filter(py_and_not_init, os.listdir(path_to_custom_dir)))
