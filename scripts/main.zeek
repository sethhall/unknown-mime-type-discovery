##! This script is to help discover new file sniffing
##! signatures based on finding files that Zeek's current
##! set of signatures doesn't yet detect. It will create a
##! new log named `unknown_mime_type_discovery.log`
##! which will contain the "begin of file buffer" (bof)
##! for any files which did not match the existing Zeek 
##! file signatures.

module UnknownMimeTypeDiscovery;

export {
	## The maximum amount of content to extract 
	## from files that don't currently have mime
	## type identification signatures.
	const max_content_extraction = 1000 &redef;

	redef enum Log::ID += {
		UnknownMimeTypeDiscovery::LOG
	};

	type Info: record {
		## Timestamp for when the file was discovered
		ts: time    &log;
		
		## File ID
		fid: string &log;

		## Begin Of File.  This is the extracted chunk of 
		## the file you can look through to create a 
		## signature to match on this file in the future.
		bof: string &log;
	};
}

event zeek_init()
	{
	Log::create_stream(UnknownMimeTypeDiscovery::LOG, 
	                   [$columns=Info, 
	                    $path="unknown_mime_type_discovery"]);
	}

event file_sniff(f: fa_file, meta: fa_metadata) &priority=-5
	{
	if ( ! meta?$mime_type && f?$bof_buffer && 
	     |f$bof_buffer| > 0 &&
	     # X509 certs will show up in here if we don't do this
	     f$source != "SSL" && f$source != "DTLS" )
		{
		Log::write(UnknownMimeTypeDiscovery::LOG,
		           Info($ts=network_time(), 
		                $fid=f$id,
		                $bof=f$bof_buffer[0:max_content_extraction]));
		}
	}

