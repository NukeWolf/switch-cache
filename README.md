# How to Run and Test / Configuration
Run with the makefile and make sure the run_script in common.mk is pointed to run_exercise.

## Configuration
h1 = 10.0.1.1

h2 = 10.0.2.2

The switch runtime is configured with the proper ipv4 forwarding table and also one table_hit entry for the cache.
When using the default server state config, the key of one is already cached in p4 tables.

## Test
When the client sends key=1, pcap files show no connection to server. 
Other values, the first requests ask the server but further request use the register cache.


# Implementation Details.

The project is based off the ipv4 forwarding rules described in the basic tutorial exercise. There is new paring logic that looks at the UDP ports and parses our new header. 

A new action is also created called cache_hit, which flips src and dst addresses, fills in the appropriate response header and invalidates the request header, and updates lenghts/checksums. 

This action is applied either on a table entry match, or whether the registery entry corresponding to the key is valid. A cache entry is split into 3 parts: the value, whether a value was present on server, and if the cache is valid.

Register Caches always write responses into its cache.

Port selection is done last using the normal ipv4 forwarding rules after possible cache hits are performed..