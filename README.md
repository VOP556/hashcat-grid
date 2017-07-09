# Hashcat Grid

This is a testing example to recover hashes with hashcat based upon a boinc infrastructure.
This project is based upon the docker-boincserver from  [marius311 boinc-server-docker](https://github.com/marius311/boinc-server-docker)

The goal of this project is to check if hash recovering could profit from be computed in a boinc based grid.

>Hashcracking is illegal in most countries. Only recover your own hashes! 

The boinc-server is docker based and the clients are baremetal in cause of the needed hardware-acceleration. The hardware-acceleration comes from hashcat itselfs.

Most of the code for workgeneration and assimilation is written in python 2.7
The validation is made by simple_validator in cause we are asume our clients are trusted


Things you'll need:

* [docker](https://www.docker.com/)
* [docker-compose](https://docs.docker.com/compose/install/)
* [boinc-Client](https://boinc.berkeley.edu/download_all.php)


## Installation of the server

Clone this project

    git clone https://github.com/VOP556/hashcat-grid.git

go into the directory and start the docker containers by typing:

    cd boinc-server-hashcat
    docker-compose --build -d

Now your server is running.

## Configure the client

Make sure your client gpu- and cpu opencl drivers are up to date.

You have to make sure, that your clients are able to resolve www.boincserver.com to the IP of your boincserver.
To ensure, write these lines to their hosts-file:

    <yourip>  www.boincserver.com

To start to compute your client have to attach to the boinc-server
For windows machines there is a powershell script:

    ./scripts/boinccmd.ps1


## Start Hashcat Job
put your hashes-file, your dictionary and your rules to:

    ./work/

and your potfile where your recoverd hashes will be written to:

    ./results/

To start a hashcat job you have to follow this syntax:

    bin/hashcat.py -a 1 -m 0 --rules work/rules --dictionary work/dictionary --hashes work/hashes --potfile-path results/potfile    

It is possible to start more than one hashcat job but they are not balanced or prioritized

## Logging
all Logfiles are here:

    /root/project/log_boincserver/


## Supported client architectures

### Windows 64 bit
* tested with Windows 7
* tested with Windows 10

### Linux 64 bit
> ToDo


## ToDo
* Linux Boinc App
* Django based Webinterface for submitting work and some management
* Hashes in Database
* Rules in Database
* Results in Database
* Rules statistics to get the most successful ones
* prioritize hashcat-jobs
