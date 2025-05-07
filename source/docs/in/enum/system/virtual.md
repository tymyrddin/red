# Scanning virtualised systems

Some systems may be running on virtual machines or containers. Depending on the configuration of the virtualisation environment, it may not be possible to communicate with some virtual machines and containers if they are not connected to the network or are configured to network with one another, but not the real network. 

In this scenario, set up a virtual machine to connect to the private virtual machine network to do a vulnerability scan or look for vulnerability scanners that can have an agent installed in the virtual machines to be scanned.