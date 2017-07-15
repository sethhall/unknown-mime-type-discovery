
Unknown MIME Type Discovery
===========================

This package is for Bro to help network analysts improve Bro 
by using their network to discover unknown file types. It 
does this by creating a log named 
``unknown_mime_type_discovery.log`` that will log a 
configurable amount of data from the beginning of any files not 
found to already have a file type detection signature in Bro.

Installation
------------

::

	bro-pkg refresh
	bro-pkg install sethhall/unknown-mime-type-discovery

Configuration
-------------

If you would like to log a different amount of the beginning of files 
with unknown mime types you can use the following configuration option
in `local.bro` or another script you are loading.  The default is to
log 1000 bytes.

::

	redef UnknownMimeTypeDiscovery::max_content_extraction = 250;
