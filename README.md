# NmapDeceiver

## What is Nmap?
Nmap (“Network Mapper”) is an open source tool for network exploration and security auditing.

Although it has a lot of useful features, there have 3 well-known features:    
 - **Host Discovery**
    -  determine what hosts are available on the network
 - **Port Scanning**
    -  what services those hosts are offering
 - **OS Detection**
    -  what operating systems (and OS versions) they are running


## Why do you need NmapDeciver?

### First step in the cyber kill chain
Network reconnaissance is the first step of the cyber kill chain from the adversaries' perspective, in this phase, adversaries may try to research, distinguish and choose the target by using reconnaissance tools (ex: Nmap, etc) to obtain critical information related to the target environment (e.g. OS version/ service/ ...).

### Why do we create NmapDeceiver?
Our Objection is to deceive the adversaries when s/he take the first step of network attack - Network reconnaissance.

We install NmapDeceiver in the router(s), so whenever we receive a Nmap scanning packet from the adversaries, we can manipulate it and send the corresponding packets back to perform the different status of our environment.


## Running NmapDeceiver

You can clone the NmapDeceiver repository for the most recent changes:

```git clone https://github.com/dy850078/NmapDeceiver.git```

The following parameters you can use after installing NmapDeceiver

```python3 main.py [--host <IP>] [--nic <nic_name>] [--scan <deceiver>] [--status <status>]```

```--host``` will allow you to specify your host that you want to protect

```--nic```  will cause NmapDeciver to send/receive packet on this nic

```--scan``` use ```hs``` / ```or``` / ```od``` to against different nmap scanning function

```--status``` determine the status of these ports (```open``` or ```close```) you want to deceive (only when you use ```--scan hs``` and we'll talk about this command in detail at next chapter)

Eg: ```python3 main.py --host 192.168.1.2 --nic eth0 --scan hs --status open``` or  

```python3 main.py --host 192.168.1.2 --scan s --status close```

### Obfuscation method

about ```--scan``` command we just descirbed aboved, you can use ```hs / or / od``` these keywords after ```--scan``` to perform different obfuscation method

- ***hs***

  port scanning deceiver

- ***od***

  os scanning deceiver

- ***or***

  record normal os packets



## Reference

Nmap doc.

https://nmap.org/docs.html

EVE-NG CookBook

https://www.eve-ng.net/index.php/documentation/community-cookbook/
