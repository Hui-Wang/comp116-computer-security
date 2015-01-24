*
* Assignment 2 - comp 116
* Author: Hui Wang
* 07-Oct-2014
---------------------------------------------

Description for the work:

1. Identify what aspects of the work have been correctly implemented and what have not.

I have implemented all of the aspects of the work.
Please note that, for a web server log that belongs to two different types of events, both of the events will be printed respectively, and counted as two events. 
	

2. Identify anyone with whom you have collaborated or discussed the assignment.

None.

3. Say approximately how many hours you have spent completing the assignment.

Roughly 10 hours total including learning Ruby.


-----------------------------------------------

Questions to be addressed:

1. Are the heuristics used in this assignment to determine incidents "even that good"?

1) For NULL scan, I used the heruistic that if there is no flag in a packet's header, it will be considered as a Null Scan. And For Xmas scan, I checked that whether a packet sets the FIN, PSH and URG flags. If so, it is considered as a Xmas Scan. I think it is a good way because it is the definitions of NULL scan and Xmas scan.

2) For credit card number leaked detection, I only detect the credit card number patterns for the four major credit card issuing networks, since it is difficult to enumerate all patterns in the world. But if we want to use this program in the real world, we would have to enumerate existing patterns as many as possible.

3) For NMAP scan detection, if there is "Nmap" keyword in the content of the log, it will be considered as Nmap scan. But as I learned from some online resources, Nmap scan would also send the “OPTIONS / HTTP/1.x″ request to the web server and the server will respond a 405 error, which means the command OPTIONS is not allowed and it can’t be executed. Maybe this situation should be taken into account ? 

4) For Shellcode detection, if there are a bunch of binary codes (in the string format of "\x...\x...\x...\x...") in the payload in a packet, my program will consider it as shellcode attack. It makes use of the property of Shellcode since it means to be executed in the remote computer. I think it is a good way to detect Shellcodes, but it is possible that some innocent requests may be judged as malicious, since we only analyze their string patterns, but not the real meanings of the codes.  


2. If you have spare time in the future, what would you add to the program or do differently with regards to detecting incidents?

1) I would add more existing patterns of credit card number into the program. 

2) I would do more research on Nmap scan, figure out all of its scan options and methods to refine the detection of it. 


