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

- ***pd***

  Port deceiver

- ***od***

  OS deceiver

- ***ts***

  Synthesize deceptive OS template
  

## Simple test

Prepare 3 hosts (or VMs), which include an attacker foothold (with Nmap), a protected server, and a DEFIC server (at least contains 2 NICs).
Make the traffic between the attacker foothold and the protected server can pass through the DEFIC server (make sure they all connect to the DEFIC server's 2 NIC respectively and then bridging the NICs)


### *OS deceiver test*

#### *STEP1: clone this repository to the DEFIC server*

```git clone https://github.com/dy850078/DEFIC_SOSLAB.git```

#### *STEP2: cd to the DEFIC_SOSLAB folder and execute the following instruction*

```python3 main.py --host <protected server's IP> --scan od --os <OS template e.g. win7/win10/centos>```

you can also designate a NIC by ```--nic```.

#### *STEP3: run Nmap OS detection on attacker foothold and observe the result*

```nmap -O <protected server's IP>```



### *Template synthesis test*

#### *STEP1: cd to the DEFIC_SOSLAB folder and execute the following instruction*

```python3 main.py --host <protected server's IP> --scan ts --os <OS template you want to synthesize e.g. win7/win10/centos>```

#### *STEP2: run Nmap OS detection on attacker foothold and observe the result*

```nmap -O <protected server's IP>```

#### *STEP3: move the template*

DEFIC will generate the template in your current directory to prevent overriding. You have to move them to ```/os_record/<OS template name>``` to deploy the template correctly.

#### *STEP4: rerun Nmap OS detection to check the template is deployed properly*

```nmap -O <protected server's IP>```



### *Port deceiver test*

#### *STEP1: cd to the DEFIC_SOSLAB folder and execute the following instruction*

```python3 main.py --host <protected server's IP> --scan pd --port <deceptive port num> --status <open|close>```

#### *STEP2: run Nmap port scanning on attacker foothold and observe the result*

```nmap -sT <protected server's IP>```

## Port Knocking
We use port knocking technology to implement the whitelist mechanism, you can use knock.py for simple testing.

#### *STEP1: set the port sequence in settings.py*
Downlad ```knock.py``` in this registry to the legal user's host and alter ```PORT_SEQ=[]``` in DEFIC server's ```DEFIC_SOSLAB/src/setting.py``` to set the port sequence.
e.g. ```PORT_SEQ=[444, 555, 666]```.

#### *STEP2: knock the sequence by knock.py*
Use legal user's host in to execute ```python3 knock.py <src_IP> <dest_IP> <p1> <p2> <p3>``` // The testing script supports 3 ports to be specified

#### *STEP3: check result*
If the legal user is added to the white_list, it will be as follows:
```
22-06-07 08:58 [INFO]: add <leagalUserIp> into white list.
22-06-07 08:58 [INFO]: {<legalUserIp_hex>: <validation_ddl>}
```
When the time limit expires, sending the packet to the protected server will display the following results:
```
22-06-07 10:00 [INFO]: <leagalUserIp> authentication is expired.
```
You can also set the validation time of whitelist via
```white_list_validation = datetime.timedelta(seconds=<validation_time>)``` in ```src/settings.py```




## Reference

Nmap doc.

https://nmap.org/docs.html

EVE-NG CookBook

https://www.eve-ng.net/index.php/documentation/community-cookbook/
