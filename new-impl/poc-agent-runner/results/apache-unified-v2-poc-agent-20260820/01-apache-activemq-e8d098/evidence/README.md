# Local verification evidence

`verify_fileserver_path.py` is a non-network receipt for the relevant source
decision at the supplied revision. It asserts the exact registration, default
configuration, authorization gate, and `RestFilter#doMove` sink tokens. It then
performs a harmless, local copy solely between controlled files in this folder.

The receipt deliberately uses generic local filenames and does not start a
server, send an HTTP request, or interact with any system outside this
workspace.
