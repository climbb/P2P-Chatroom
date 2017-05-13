#!/usr/bin/python3

# Student name and No.: LAI CHEUK HIN
# Student name and No.: LEUNG LOK MING
# Development platform: macOS Sierra 10.12
# Python version: 3.5.2
# Version: 1.0.0


from tkinter import *
import sys
import socket
import time
import threading
import select

#
# Global variables
#

isconnectedrmserver = False
CONNECTED = False
isjoined = False
scheduleForwardLink = False

# The JOIN message

keepaliveMsg = '' 

# Room server socket
rmserversockfd = socket.socket()

# Room name
rmname = ''

msgID = 0

# Member list

memberList = []

# Storing the member object and the hashID of the backwardlink peer

backwardLinkMemberList = []
backwardLinkHashIDList = []

# Storing the sockets

backwardLinkList = []
forwardLinkList = []

# Storing threads

thdList = []

username = ''
myIP = ''
myPort = ''
myHashID = ''

RList = []

class Member:

	def __init__(self, username, IP, port):
		self.username = username
		self.IP = IP
		self.port = port
		self.HashID = sdbm_hash(self.username+self.IP+self.port)


#
# This is the hash function for generating a unique
# Hash ID for each peer.
# Source: http://www.cse.yorku.ca/~oz/hash.html
#
# Concatenate the peer's username, str(IP address), 
# and str(Port) to form the input to this hash function
#
def sdbm_hash(instr):
	hash = 0
	for c in instr:
		hash = int(ord(c)) + (hash << 6) + (hash << 16) - hash
	return hash & 0xffffffffffffffff

#
# Functions to handle user input
#

######################################################################################
#																					 #
# The debug messages in the format of "[System]" also explain how the program works, #
# so take a look at them! :)														 #
#																					 #
######################################################################################


def do_User():

	global username, isjoined

	if isjoined:
		outstr = '\nChanging username after JOINED is not allowed!'
		CmdWin.insert(1.0, outstr)

	else:

		# Get the user input to be the username

		inputName = userentry.get()

		if inputName == '':
			outstr = '\nPlease enter a non-empty username!'
			CmdWin.insert(1.0, outstr)
		else:
			outstr = "\n[User] username: "+userentry.get()
			CmdWin.insert(1.0, outstr)
			username = str(userentry.get())
			userentry.delete(0, END)



def do_List():

	global rmserversockfd, isconnectedrmserver

	if isconnectedrmserver == False:

		# If the client has not connected to the room server,
		# then connect to it.

		try:
			rmserversockfd.connect((sys.argv[1], int(sys.argv[2])))
			isconnectedrmserver = True
		except socket.error as emsg:
			print("Socket bind error: ", emsg)
	
	# ready the LIST request
	msg = 'L::\r\n'

	# send it to the room server
	rmserversockfd.send(msg.encode('ascii'))

	rmsg = rmserversockfd.recv(1024)
	serverResponse = str(rmsg)

	if serverResponse[2] == "G":

		# get the correct response from the room server
		# split the response by the ':'

		rmList = serverResponse.split(':')

		if (len(rmList) == 3) and (rmList[1] == ''):

			# If the response message does not have anything in the middle,
			# that means no active chatrooms

			outstr = '\nNo active chatrooms'
			CmdWin.insert(1.0, outstr)

		else:

			# Print out every room name

			for rmName in rmList[1:len(rmList)-2]:
				CmdWin.insert(1.0, '\n	' + rmName)
			outstr = '\nHere are the active chatrooms:'
			CmdWin.insert(1.0, outstr)

	else:

		# We encounter some error in the server

		rList = serverResponse.split(':')
		CmdWin.insert(1.0, rList[0])

def do_Join():
	global serverResponse, myPort, myIP, myHashID, scheduleForwardLink, keepaliveMsg, msgID, rmname, rmserversockfd, isconnectedrmserver, username, memberList, isjoined

	# Check if the username is typed in

	if username == '':
		outstr = '\nPlease enter you username first.'
		CmdWin.insert(1.0, outstr)

	# Check if the user is joining in the chat

	else:
		if isjoined:
			outstr = '\nYou have been joining the chat.'
			CmdWin.insert(1.0, outstr)

		else:

			# If the client has not connected to the room server,
			# then connect to it.

			if isconnectedrmserver == False:
				print('[System][Join] Connect the socket for the room server.')
				try:
					rmserversockfd.connect((sys.argv[1], int(sys.argv[2])))
				except socket.error as emsg:
					print("Socket bind error: ", emsg)

				isconnectedrmserver = True

			rmname = userentry.get()

			# Get the client IP, port and hashID and save it into global variable

			myIP = socket.gethostbyname(socket.gethostname())
			myPort = sys.argv[3]
			myHashID = sdbm_hash(username+myIP+myPort)
			keepaliveMsg = 'J:' + rmname + ':' + username + ':' + myIP + ':' + myPort + '::\r\n'

			# Send out the keepalive message

			rmserversockfd.send(keepaliveMsg.encode('ascii'))
			print('[System][Join] Sent a JOIN request to the room server.')

			rmsg = rmserversockfd.recv(1024)
			serverResponse = str(rmsg)


			if serverResponse[2] == "M":

				print('[System][Join] Get the response from the room server.')

				outstr = '\nMy IP adress: ' + myIP + ' My listening port: ' + myPort
				CmdWin.insert(1.0, outstr)

				isjoined = True
				userentry.delete(0, END)

				# A combined thread of Keepalive (sending JOIN message to the roomserver and keep forwardlinking)

				t = threading.Thread(name="Keepalive", target=keepalive_thd)
				t.start()
				thdList.append(t)
				CmdWin.insert(1.0, "\nKeepalive thread - Start execution")

				# Open for TCP connection

				t2 = threading.Thread(name="TCP", target=listenTCP)
				t2.start()
				thdList.append(t2)


	
def keepalive_thd():

	# A thread for sending out keepalive message and establish forwardlink

	global rmserversockfd, keepaliveMsg, serverResponse

	print ("[System][keepalive_thd] A keepalive threand is executing.")

	rmserversockfd.send(keepaliveMsg.encode('ascii'))

	print ("[System][keepalive_thd] A keepalive message has been sent.")

	# Update the member list

	serverResponse = str(rmserversockfd.recv(1024))

	gList = []
	rList = serverResponse.split(':')
	noOfMember = (len(rList)-4)/3

	i = 0
	while i < noOfMember:
		gList.append(Member(rList[2+3*i],rList[3+3*i],rList[4+3*i]))
		i+=1

	memberList = gList

	print ("[System][keepalive_thd] Member list has been successfully updated.")
	print ("[System][keepalive_thd] Go into the forwardlink process now.")

	forwardLink()

	# Do it after a few seconds

	win.after(20000, keepalive_thd)

	

def forwardLink():

	# The funciton for establishing a forwardlink, following the logic in the instrcution

	global RList, serverResponse, myPort, myIP, backwardLinkMemberList, scheduleForwardLink, msgID, rmname, rmserversockfd, isconnectedrmserver, username, memberList, backwardLinkList, forwardLinkList
		
	gList = []
	rList = serverResponse.split(':')
	MSID = rList[1]
	noOfMember = (len(rList)-4)/3

	i = 0
	while i < noOfMember:
		gList.append(Member(rList[2+3*i],rList[3+3*i],rList[4+3*i]))
		i+=1

	memberList = gList

	print ("[System][forwardLink] Member list has been successfully updated.")

	# Sort the gList

	gList.sort(key=lambda member: member.HashID)

	# Create one more list for storing HashID, so that we can do comparison later

	HashIDList = []

	for g in gList:
		HashIDList.append(g.HashID)

	# Sort the HashID list as well

	HashIDList.sort()

	myHashID = sdbm_hash(username + myIP + myPort)

	# If there is no fowardlink socket currently

	if(len(forwardLinkList) == 0):
		print("[System][forwardLink] No forwardLink. Search for forwardLink")
		X = HashIDList.index(myHashID)
		start = X+1

		if start >= len(HashIDList):
			start = 0

		while HashIDList[start] != myHashID:
			if HashIDList[start] in backwardLinkHashIDList:

				# The peer has already established a backwardlink, that means we cannot make
				# forwardlink to it

				print("[System][forwardLink] " + gList[start].username + " has already established a backwardlink to you, try next target.")
				start = (start + 1)%  len(gList)
				continue
			else:
				try:
					print ("[System][forwardLink] A suitable peer is found.")
					peerUsername = gList[start].username
					peerIP = gList[start].IP
					peerPort = gList[start].port
					peerSocekt = socket.socket()
					print ("[System][forwardLink] The peer is: " + peerUsername + " [IP:" + peerIP + "] [Port:" + peerPort + "]")

					# Send the PEER-to-peer handshake message to the peer 

					peerSocekt.connect((peerIP,int(peerPort)))
					handshake = "P:" + rmname + ":" + username + ":" + myIP + ":" + myPort + ":" + str(msgID) + "::\r\n"
					peerSocekt.send(handshake.encode('ascii'))
					peerrm = peerSocekt.recv(1024)
					peerrmsg = str(peerrm)
					

					if peerrmsg[2] == "S":
						print ("[System][forwardLink] PEER-to-peer handshake is successfully done.")
						rList = peerrmsg.split(':')
						peermsgID = rList[1]
						msgID = int(peermsgID)

						CmdWin.insert(1.0, "\nSuccessfully linked to the group - via " + gList[start].username)
						RList.append(peerSocekt)
						forwardLinkList.append(peerSocekt)
						break

					else:
						CmdWin.insert(1.0, "\nCannot establish forward link to the peer, try to connect another user...")
						peerSocekt.close()
						start = (start+1) % len(HashIDList)
						continue

				except socket.error as emsg:
					CmdWin.insert(1.0, "\nSocket error in TCP connection to a member: "+str(emsg))
					start = (start+1) % len(HashIDList)
					continue

	if(len(forwardLinkList) == 0):
		print("[System][forwardLink] Fail to establish a forward link. Try later...")
		scheduleForwardLink = True


def listenTCP():

	# When the program starts this function, the TCP connection would be opened

	global CONNECTED, RList, keepaliveMsg, myPort, backwardLinkHashIDList, backwardLinkMemberList, msgID, rmname, rmserversockfd, isconnectedrmserver, username, memberList, backwardLinkList, forwardLinkList
	
	CONNECTED = True # Variable indicating the connection, used in the termination process

	listenSocket = socket.socket()

	# Create socket and bind

	try:
		listenSocket.bind(('', int(myPort)))
	except socket.error as emsg:
		CmdWin.insert(1.0, "\nSocket error: "+str(emsg))

	listenSocket.listen(5)

	RList.append(listenSocket)

	while CONNECTED :
		try:
			Rready, Wready, Eready = select.select(RList, [], [], 10)
		except select.error as emsg:
			print("[System][listenTCP] At select, caught an exception:", emsg)
			sys.exit(1)

		if Rready:

			# for each socket in the READ ready list
			
			for sd in Rready:

				if sd == listenSocket:

					# A backwardlink is coming

					newfd, caddr = listenSocket.accept()
					CmdWin.insert(1.0, "\nBackwardlink established")
					RList.append(newfd)
					backwardLinkList.append(newfd)

				else:
					rm = sd.recv(1024)
					if rm:

						rmsg = str(rm)
						print ('[System][listenTCP] Receive a message: ' + rmsg)

						if rmsg[2] == 'P':

							# The incoming message is a PEER-to-peer handshaking message

							print ('[System][listenTCP] Receive a PEER-to-peer handshaking procedure.')
							argList = rmsg.split(':')
							newPeer = Member(argList[2], argList[3], argList[4])
							print("[System][listenTCP] The information of the requester:\nUsername: " + newPeer.username + "\nIP: " + newPeer.IP + "\nPort: " + newPeer.port)

							# Get the latest member list and update it
							rmserversockfd.send(keepaliveMsg.encode('ascii'))
							serverResponse = str(rmserversockfd.recv(1024))

							gList = []
							rList = serverResponse.split(':')
							noOfMember = (len(rList)-4)/3

							i = 0
							while i < noOfMember:
							 	gList.append(Member(rList[2+3*i],rList[3+3*i],rList[4+3*i]))
							 	i+=1

							memberList = gList

							#Create a local HashID list for checking
							HashIDList = []

							for g in gList:
							 	HashIDList.append(g.HashID)

							if newPeer.HashID in HashIDList:
								print('[System][listenTCP] Confirmed that the requester is a member in th chatroom')
								backwardLinkMemberList.append(newPeer)
								backwardLinkHashIDList.append(newPeer.HashID)
								reply = "S:" + str(msgID) + "::\r\n"
								print('[System][listenTCP] Try to send the response.')
								try:
									sd.send(reply.encode('ascii'))
									CmdWin.insert(1.0, "\n"+ backwardLinkMemberList[-1].username +" has linked to me")
								except socket.error as emsg:
									print("encounter error when sending the S: message")

							else:
							 	RList.remove(sd)
							 	sd.close()
							 	CmdWin.insert(1.0, "The handshaking procedure is unsuccessful.")


						elif rmsg[2] == 'T':

							# The incoming message is a TEXT message

							argList = rmsg.split(':')
							textRmName = argList[1]
							textHID = argList[2]
							textUsername = argList[3]
							textMsgID = argList[4]
							textMsgLength = argList[5]
							textMsglist = argList[6:-2]
							print(textMsglist)
							textMsg = ':'.join(textMsglist)

							if rmname == argList[1]:

								# If the message IDs match
								if int(textMsgID) == msgID:

									MsgWin.insert(1.0, "\n["+textUsername+"] "+textMsg)
									msgID+=1

									for f in forwardLinkList:
										if f != sd:
											print ('[System][listenTCP] Sending a message to forwardlink')
											CmdWin.insert(1.0, "\nRelay the message to other peer")
											f.send(rm)

									for b in backwardLinkList:
										if b != sd:
											print ('[System][listenTCP] Sending a message to backwardlink')
											CmdWin.insert(1.0, "\nRelay the message to other peer")
											b.send(rm)

							else:
								CmdWin.insert(1.0, "\nError: Message from other chatroom received")


					else:

						# Else, that means a connection is broken

						print('[System][listenTCP] Connection broken!')
						RList.remove(sd)
						if sd in forwardLinkList:
							forwardLinkList.remove(sd)
							CmdWin.insert(1.0, "\nA Forward connection broke! Will be reconnected after new member list updated")
						elif sd in backwardLinkList:
							backwardLinkList.remove(sd)
							CmdWin.insert(1.0, "\nA backward connection broke!")
						sd.close()

	# When CONNECT is set to False, the program would escape from the while loop
	# It is time to close all the sockets

	print('[System][listenTCP] Escaped from the loop. Start closing all the sockets.')
	for b in backwardLinkList:
		b.close()
	for f in forwardLinkList:
		f.close()
	for r in RList:
		r.close()
	RList = []



def do_Send():
	global RList, serverResponse, myPort, myIP, myHashID, backwardLinkMemberList, scheduleForwardLink, msgID, rmname, rmserversockfd, isconnectedrmserver, username, memberList, backwardLinkList, forwardLinkList, isjoined

	if userentry.get() == "":
		CmdWin.insert(1.0, "\nMessage cannot be blanked.")
	else:
		if isjoined:	# Check if the client is connected to a chat room
			msg = userentry.get()
			length = len(msg)
			sendmsg = "T:"+rmname+":"+str(myHashID)+":"+username+":"+str(msgID)+":"+str(length)+":"+str(msg)+"::\r\n"
			msgID += 1

			# Send the message to both forwardlink and backwardlink

			for f in forwardLinkList:
				f.send(sendmsg.encode('ascii'))
			for b in backwardLinkList:
				b.send(sendmsg.encode('ascii'))

			# Display the message on screen

			MsgWin.insert(1.0, "\n["+username+"] "+msg)

		else:
			CmdWin.insert(1.0, "\nYou are not connected to any chatroom.")
		userentry.delete(0, END)



def do_Quit():
	global CONNECTED, thdList, RList, rmserversockfd

	# set the CONNECTED to False, so that the while loop in listenTCP() will be broken

	CONNECTED = False

	try:
		if len(thdList) > 0:
			while len(RList) != 0: 
				# Wait for all socket to be closed
				continue

			# Kill all the thread
			thdList[0].join

		# Close the socket connected to room server
		rmserversockfd.close()

	except socket.error as emsg:
		print("Socket close error: ", emsg)

	sys.exit(0)

#
# Set up of Basic UI
#
win = Tk()
win.title("MyP2PChat")

#Top Frame for Message display
topframe = Frame(win, relief=RAISED, borderwidth=1)
topframe.pack(fill=BOTH, expand=True)
topscroll = Scrollbar(topframe)
MsgWin = Text(topframe, height='15', padx=5, pady=5, fg="red", exportselection=0, insertofftime=0)
MsgWin.pack(side=LEFT, fill=BOTH, expand=True)
topscroll.pack(side=RIGHT, fill=Y, expand=True)
MsgWin.config(yscrollcommand=topscroll.set)
topscroll.config(command=MsgWin.yview)

#Top Middle Frame for buttons
topmidframe = Frame(win, relief=RAISED, borderwidth=1)
topmidframe.pack(fill=X, expand=True)
Butt01 = Button(topmidframe, width='8', relief=RAISED, text="User", command=do_User)
Butt01.pack(side=LEFT, padx=8, pady=8);
Butt02 = Button(topmidframe, width='8', relief=RAISED, text="List", command=do_List)
Butt02.pack(side=LEFT, padx=8, pady=8);
Butt03 = Button(topmidframe, width='8', relief=RAISED, text="Join", command=do_Join)
Butt03.pack(side=LEFT, padx=8, pady=8);
Butt04 = Button(topmidframe, width='8', relief=RAISED, text="Send", command=do_Send)
Butt04.pack(side=LEFT, padx=8, pady=8);
Butt05 = Button(topmidframe, width='8', relief=RAISED, text="Quit", command=do_Quit)
Butt05.pack(side=LEFT, padx=8, pady=8);

#Lower Middle Frame for User input
lowmidframe = Frame(win, relief=RAISED, borderwidth=1)
lowmidframe.pack(fill=X, expand=True)
userentry = Entry(lowmidframe, fg="blue")
userentry.pack(fill=X, padx=4, pady=4, expand=True)

#Bottom Frame for displaying action info
bottframe = Frame(win, relief=RAISED, borderwidth=1)
bottframe.pack(fill=BOTH, expand=True)
bottscroll = Scrollbar(bottframe)
CmdWin = Text(bottframe, height='15', padx=5, pady=5, exportselection=0, insertofftime=0)
CmdWin.pack(side=LEFT, fill=BOTH, expand=True)
bottscroll.pack(side=RIGHT, fill=Y, expand=True)
CmdWin.config(yscrollcommand=bottscroll.set)
bottscroll.config(command=CmdWin.yview)

def main():
	if len(sys.argv) != 4:
		print("P2PChat.py <server address> <server port no.> <my port no.>")
		sys.exit(2)


	win.mainloop()

if __name__ == "__main__":
	main()

