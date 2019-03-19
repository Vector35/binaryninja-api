import sys

# invoked from python2 command line? (eg: python -m kaitai ...)
if sys.version_info[0] == 2 and sys.argv[0:] and sys.argv[0]=='-c':
	pass
# invoked from python3 command line? (eg: python -m kaitai ...)
elif sys.version_info[0] == 3 and sys.argv[0:] and sys.argv[0]=='-m':
	pass
# invoked from binja
else:
	if sys.version_info[0] == 2:
		import view
	else:
		from . import view
