'''
Readline path completer, modified snippet from:
https://stackoverflow.com/questions/5637124/tab-completion-in-pythons-raw-input
'''

import os
import readline

def _listdir(root):
   ''' List directory 'root' appending the path separator to subdirs. '''
   res = []
   for name in os.listdir(root):
      path = os.path.join(root, name)
      if os.path.isdir(path):
         name += os.sep
      res.append(name)
   return res

def _complete_path(path=None):
   ''' Perform completion of filesystem path. '''
   if not path:
      return _listdir('.')

   dirname, rest = os.path.split(path)
   tmp = dirname if dirname else '.'
   res = [os.path.join(dirname, p) for p in _listdir(tmp) if p.startswith(rest)]

   # more than one match, or single match which does not exist (typo)
   if len(res) > 1 or not os.path.exists(path):
      return res
   # resolved to a single directory, so return list of files below it

   if os.path.isdir(path):
      return [os.path.join(path, p) for p in _listdir(path)]

   # exact file match terminates this completion
   return [path + ' ']

def complete(text, state):
   buffer = readline.get_line_buffer()
   return (_complete_path(buffer)+[None])[state]
