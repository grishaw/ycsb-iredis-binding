# ycsb-iredis-binding

This is a proof-of-concept implementation of the ideas presented in the "Crowdsourced Data Integrity Verification for  Key-Value Stores in the Cloud" paper (CCGRID-2017).

## Installation
* Download the YCSB project from https://github.com/brianfrankcooper/YCSB.git
* Include this module (https://github.com/grishaw/ycsb-iredis-binding.git) under the YCSB directory
* Add \<iredis\> to the list of the modules in YCSB/pom.xml
* In binding-properties file add the following: "iredis: iredis.IRedisClient"
* To build: mvn clean package

## Running a workload
Running a workload for IRedisClient is similar to the running of YCSB-RedisClient workload. 
The only difference is that the following paramers must be specified:
* i.bulk.size - defines a number of tuples in a bulk
* i.p.param - parameter p (defines how many tuples will be linked to each tuple)
* i.auth.key - secret key for data authentication
* i.enc.key - secret key for data encryption

### Example of load command:
ycsb.bat load iredis -s -P workloads/workloadc -p redis.host=localhost -p i.bulk.size=1000 -p i.p.param=4 -p i.enc.key=1234567890abcdef -p i.auth.key=abcdef1234567890
