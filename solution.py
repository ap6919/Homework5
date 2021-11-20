from socket import *
import os
import sys
import struct
import time
import select
import binascii

ICMP_ECHO_REQUEST = 8
MAX_HOPS = 30
TIMEOUT = 2.0
TRIES = 1
# The packet that we shall send to each router along the path is the ICMP echo
# request packet, which is exactly what we had used in the ICMP ping exercise.
# We shall use the same packet that we built in the Ping exercise

def checksum(string):
# In this function we make the checksum of our packet
    csum = 0
    countTo = (len(string) // 2) * 2
    count = 0

    while count < countTo:
        thisVal = (string[count + 1]) * 256 + (string[count])
        csum += thisVal
        csum &= 0xffffffff
        count += 2

    if countTo < len(string):
        csum += (string[len(string) - 1])
        csum &= 0xffffffff

    csum = (csum >> 16) + (csum & 0xffff)
    csum = csum + (csum >> 16)
    answer = ~csum
    answer = answer & 0xffff
    answer = answer >> 8 | (answer << 8 & 0xff00)
    return answer

def build_packet():
    #Fill in start
    # In the sendOnePing() method of the ICMP Ping exercise ,firstly the header of our
    # packet to be sent was made, secondly the checksum was appended to the header and
    # then finally the complete packet was sent to the destination.

    # Make the header in a similar way to the ping exercise.
    # Append checksum to the header.
    #Create packet similar to homework 4
    myID = os.getpid() & 0xFFFF 
    # Header is type (8), code (8), checksum (16), id (16), sequence (16)

    myChecksum = 0
    # Make a dummy header with a 0 checksum
    # struct -- Interpret strings as packed binary data
    header = struct.pack("bbHHh", ICMP_ECHO_REQUEST, 0, myChecksum, myID, 1)
    data = struct.pack("d", time.time())
    # Calculate the checksum on the data and the dummy header.
    myChecksum = checksum(header + data)

    # Get the right checksum, and put in the header

    if sys.platform == 'darwin':
        # Convert 16-bit integers from host to network  byte order
        myChecksum = htons(myChecksum) & 0xffff
    else:
        myChecksum = htons(myChecksum)
    header = struct.pack("bbHHh", ICMP_ECHO_REQUEST, 0, myChecksum, myID, 1)

    # Don’t send the packet yet , just return the final packet in this function.
    #Fill in end

    # So the function ending should look like this

    packet = header + data
    return packet

def get_route(hostname):
    timeLeft = TIMEOUT
    tracelist1 = [] #This is your list to use when iterating through each trace 
    tracelist2 = [] #This is your list to contain all traces

    for ttl in range(1,MAX_HOPS):
        tracelist1 = [] # Reset list for this trace attempt
        for tries in range(TRIES): 
            destAddr = gethostbyname(hostname) #Gets ip address of traceroute query
            #Fill in start
            # Make a raw socket named mySocket
            icmp = getprotobyname("icmp") 
            mySocket = socket(AF_INET, SOCK_RAW, icmp) #create socket that accepts icmp requests
            #Fill in end
            mySocket.setsockopt(IPPROTO_IP, IP_TTL, struct.pack('I', ttl))
            mySocket.settimeout(TIMEOUT)
            try:
                d = build_packet() #builds packet
                mySocket.sendto(d, (destAddr, 0)) #sends packet to fqdn
                t=time.time() #timestamps for no reason? might be for sending time but thats in packet
                startedSelect = time.time() #timestamps again
                whatReady = select.select([mySocket], [], [], timeLeft) #Creates a timer for socket, will throw timeout error
                howLongInSelect = (time.time() - startedSelect) #decides how long select has been running
                if whatReady[0] == []: # Timeout - If nothing is ready
                    tracelist1.append(str(ttl)) #add which step it is
                    tracelist1.append("*") # padding
                    tracelist1.append("Request timed out.") #Error
                    print(f"{str(ttl)} Request Timed Out") 
                    #Fill in start
                    #You should add the list above to your all traces list
                    tracelist2.append(tracelist1) # Adds Trace to our master list
                    #Fill in end
                recvPacket, addr = mySocket.recvfrom(1024) #gets a packet and return address
                timeReceived = time.time() #takes a time stamp of when it as received
                timeLeft = timeLeft - howLongInSelect #decides if a packet has waited too long.
                if timeLeft <= 0:
                    tracelist1.append(str(ttl)) #add which step it is
                    tracelist1.append("*") # padding
                    tracelist1.append("Request timed out.") #Error
                    print(f"{str(ttl)} Request Timed Out") 
                    #Fill in start
                    #You should add the list above to your all traces list
                    tracelist2.append(tracelist1) # Adds Trace to our master list
                    #Fill in end
            except timeout: #seems to only come from line 82 but does nothing
                continue

            else: # if there is a response
                types = struct.unpack("bbHHh", recvPacket[20:28])[0] #Fetch the icmp type from the IP packet
                sourceIP = addr[0] # _RetAddr form socket
                bytes = struct.calcsize("d") #extrenuous from skeleton code
                timeSent = struct.unpack("d", recvPacket[28:28 + bytes])[0] #extrenuous from skeleton code
                timeTaken = str(int((timeReceived-t)*1000))+"ms" #based on t(line 80) and timeReceived(line 94)
                #Fill in end
                try: #try to fetch the hostname
                    #Fill in start TODO 
                    sourceHost = gethostbyaddr(sourceIP)[0] #uses same library to get FQDN from ip 
                    if not sourceHost:#make an error if it returns nothing
                        raise herror
                    #Fill in end
                except herror:   #if the host does not provide a hostname
                    #Fill in start TODO
                        sourceHost = "hostname not returnable"
                    #Fill in end

                if types == 11: #ttl Expired
                    #Fill in start TODO
                    tracelist2.append([str(ttl),timeTaken,sourceIP,sourceHost]) # append trace to master list
                    print(f"{str(ttl)} {timeTaken} {sourceIP} {sourceHost}")
                    #You should add your responses to your lists here
                    #Fill in end
                elif types == 3: #Host Unreachable
                    #Fill in start TODO
                    tracelist2.append([str(ttl),timeTaken,sourceIP,sourceHost]) # append trace to master list
                    print(f"{str(ttl)} {timeTaken} {sourceIP} {sourceHost}")
                    #You should add your responses to your lists here 
                    #Fill in end
                elif types == 0: #Successful ping
                    #Fill in start TODO
                    tracelist2.append([str(ttl),timeTaken,sourceIP,sourceHost]) # append trace to master list
                    #You should add your responses to your lists here and return your list if your destination IP is met
                    print(f"{str(ttl)} {timeTaken} {sourceIP} {sourceHost}")
                    if sourceIP == destAddr: #if ip from _RetAddr is equal to destAddr
                        print(f"{type(tracelist2)}: {tracelist2}")
                        return tracelist2 #return final list
                    #Fill in end
                else: #any other
                    #Fill in start TODO
                    tracelist2.append([str(ttl),timeTaken,sourceIP,sourceHost])
                    #If there is an exception/error to your if statements, you should append that to your list here
                    print(f"{str(ttl)} {timeTaken} {sourceIP} {sourceHost}")
                    #Fill in end
                break
            finally:
                mySocket.close()
    print(f"{type(tracelist2)}: {tracelist2}")
    return(tracelist2)

if __name__ == "__main__":
    print("test")
    print(get_route("google.com"))
   
