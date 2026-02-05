# website Fingerprinting

#### This lab attempts to reproduce the results of previous closed-world website fingerprinting research against modern Tor defenses.

A directory is included w/ the relevant container names - these should be left as is. A docker compose script has been included to spin up the network. Docker must be installed for the following to work as intended. In the parent directory use:

                `sudo ./docker_run.sh`

    - This will start all the required containers and test routing. If this file does not run, `chmod +x [filename]` might be required to make it executable.


To run the Python script you can use:

        `sudo python3 main.py` 
        
        It will also take additional options like -l (the url list) -r (number of runs) -i (your network interface) 

To spin down the network use:

            `docker compose down`

### To Do:

Bind a mount to the docker containers and keep the required files/scripts within so they wouldn't need to be copied over every run 

Implement automation logic including:

- Alice container launching Tor client and crawler script
  
    - [ ] Test Alice container w/ crawler script
  
    - [ ] Test Alice container w/ tor client running and crawler script

- Bob container capturing Alice traffic and analyzing (creating monitored set to be done before or during?)
  
    - [ ] Add logic to anlyze script: compile and normalize without compare
  
    - [ ] Fix analyze script bug
  
    - [ ] Test tcpdump automation with bob container






