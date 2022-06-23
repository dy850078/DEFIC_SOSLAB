# DEFIC

## What is Nmap?
Nmap (“Network Mapper”) is an open source tool for network exploration and security auditing.

Although it has a lot of useful features, there have 3 well-known features:    
 - **Host Discovery**
    -  determine what hosts are available on the network
 - **Port Scanning**
    -  what services those hosts are offering
 - **OS Detection**
    -  what operating systems (and OS versions) they are running


## Why do you need DEFIC?

### First step in the cyber kill chain & MITRE&CK
Network reconnaissance stands the first stage of a cyber kill chain, where adversaries conduct host discovery, port scanning, and operating system detection in order to obtain critical information from remote hosts. 

### Why do we create DEFIC?
Our primary purpose is to install a defensive deception solution on the target network, transparently sniffing malicious and normal traffic and forging the real host responses. DEFIC can mimic a target system to scrub the real identity of systems behind it.

## Running DEFIC

You can clone this repository for the most recent changes:

```git clone https://github.com/dy850078/DEFIC_SOSLAB.git```

The following parameters you can use after installing NmapDeceiver

```python3 main.py [--host <IP>] [--nic <nic_name>] [--scan <deceiver>] [--status <status>]```

```--host``` will allow you to specify your host that you want to protect

```--nic```  will cause NmapDeciver to send/receive packet on this nic

```--scan``` use ```ts``` for OS template synthesis, ```od``` for os deceiver, ```hs``` for port deceiver

```--status``` determine the status of these ports (```open``` or ```close```) you want to deceive (only when you use ```--scan hs``` and we'll talk about this command in detail at the next chapter)

Eg: ```python3 main.py --host 192.168.1.2 --nic eth0 --scan hs --status open``` or  

```python3 main.py --host 192.168.1.2 --scan od --os win7```

### Obfuscation method

about ```--scan``` command we just descirbed aboved, you can use ```hs / or / od``` these keywords after ```--scan``` to perform different obfuscation method

- ***hs***

  Port deceiver

- ***od***

  OS deceiver

- ***ts***

  Synthesizee deceived OS template
  

### Simple test

Prepare 3 hosts (or VMs) which include a attaker foothold (with Nmap), a victim, and a deceiver (at least contains 2 NICs).
Make the traffic between the attacker foothold and the victim can pass through the deceiver (by connecting each of them to the decevier's 2 NIC respectively and bridge the NICs)

*clone this repository to the deceiver*

```git clone https://github.com/dy850078/DEFIC_SOSLAB.git```

*cd to the DEFIC_SOSLAB and execute the following instruction*

```python3 main.py --host <victim's IP> --scan od --os <OS template e.g. win7/win10/centos>```

you can also designate a NIC by ```--nic```.

*run Nmap OS detection on attacker foothold and observe the result*

```nmap -O <vimtim's IP>```



## Reference

Nmap doc.

https://nmap.org/docs.html

EVE-NG CookBook

https://www.eve-ng.net/index.php/documentation/community-cookbook/
