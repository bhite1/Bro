event bro_init() &priority=0
    {
        print "Bro Init";
    	local source: string = "evidence06.pcap";
    	Input::add_analysis([$source=source, $name=source]);
    }

event file_hash(f: fa_file, kind: string, hash: string)
    {
        print "file_hash", f$id, kind, hash;
    }

event file_new(f: fa_file)
    {
    	print "new file", f$id;
    	Files::add_analyzer(f, Files::ANALYZER_MD5);
    }

event bro_done()
	{
        print "Bro Done";
	}