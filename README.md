# Banking Monster-in-the-Middle (MITM)


## Background
<img width="1237" alt="Screen Shot 2021-06-15 at 10 37 39 AM" src="https://user-images.githubusercontent.com/55666152/122100093-a4ae3b80-cdc7-11eb-8031-9a5094ee81ae.png">
Since there is no authentication in DNS and no encryption in HTTP, attackers might exploit such vulnerability by replying a DNS query with a false IP address, thereby tricking clients into connecting to the wrong IP address for the domain. Attackers can eavesdrop and modify the comminucation between two parties who think they are comminucating with each other directly. We call such attack as monster-in-the-middle network attack (MITM). <br><br>

In this project, we will perform a MITM attack as an attacker. And we divide the attack into two parts:
 * **DNS attack**: When the client queries a DNS A record for fakebank.com, the attack sends back a spoofed DNS response containing the attacker’s IP address.
 * **HTTP attack**: The attacker listens for HTTP requests, forward them to the bank server, and return the response from the server back to the client unchanged.

## Files
* correct_mitm_output.txt: 
* /network/client: simulate the behavior of an oblivious client that will fall victim to your monster-in-the-middle.
* /network/dns: simulate the behavior of an innocent DNS server
* /network/http: simulate the behavior of a true HTTP server (fakebank.com)
* mitm.go: simulate the behavior of the mitm attacker

## How to run
* Install (and run) Docker Community Edition on your local machine: https://store.docker.com/search?type=edition&offering=community
* To build the images that will be running the backend http and dns servers: run `bash start_images.sh` 

  re-run this command everytime files in network/ directory get modified
* To test your `mitm.go` implementation, run `bash run_client.sh`

  re-run this command everytime `mitm.go` gets updated
* To stop docker images: run `bash stop_images.sh`
* completely remove the unused images and containers from your machine: run `docker system prune -a`.
* To clean up files related to previous instances: run `docker system prune -a`

Note: If you are on Linux, you will have to run the above commands with `sudo` privileges. 

## How to check:
`correct_mitm_output.txt` is what you should see after implementing the MITM completely. In other words, your output when running `bash run_client.sh` should match the contents of the `correct_mitm_output.txt` file, with the exception that the lines beginning with `tcpdump` don't need to exactly match.

