ShowAdCerts
===========

A tool to examine and verify PKI certificates within Active Directory

Switches (all are optional): 

-h  host or domain name (default = default logon server)
-f  ldap filter         (default = userCertificate=*   )
-b  search base         (default = domain root NC      )
-v  (turn on cert validation of non-expired certs      )
-r  (dump raw cert data                                )

This utility works very nicely with the openssl commandline tools, e.g.:
ShowAdCerts -f sn=smith -r | openssl x509 -text