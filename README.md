# NmapDeceiver

## What is Nmap?
Nmap (“Network Mapper”) is an open source tool for network exploration and security auditing. 

Although it has a lot of useful features, there have 3 features which is well known:    
 - **Host Discovery**
    -  determine what hosts are available on the network 
 - **Port Scanning**
    -  what services those hosts are offering
 - **OS Detection**
    -  what operating systems (and OS versions) they are running


## Why you need NmapDeciver?

### First step in the cyber kill chain
Network reconnaissance is the first step of the cyber kill chain from the adversaries' perspective, in this phase, adversaries may try to research, distinguish and choose the target by using reconnaissance tools (ex: Nmap) to obtain information related to this target environment.

### Why did we create NmapDeceiver?
Our Objection is to deceive the adversaries when s/he take the first step of network attack - Network reconnaissance 

We place NmapDeceiver in the router, so whenever we receive Nmap scanning packet from the adversaries, we can send the corresponding packets back to pretend the fake status of our environment according to Nmap scanning rules


## Running NmapDeceiver

You can clone the NmapDeceiver repository for the most recent changes:
```git clone https://github.com/dy850078/NmapDeceiver.git```

The following parameters you can use after installing NmapDeceiver

```python3 main.py [--host] [--port] [--nic] [--sT] [--hs] [--open] [--close]```
