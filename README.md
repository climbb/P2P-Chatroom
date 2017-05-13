# P2P-Chatroom
An instant chat program that supports message written in Python.

To find out which chatroom groups are available and discover the
contact information of all group members in the chatroom, the system uses a Room server to keep track of
the information. 

# Run

1. Run the **room_server_64** or **room_server_mac** depending on which OS you're using.
2. Run the **P2PChat.py** in Python3. The P2PChat program accepts three command line arguments:
```
P2PChat <roomserver_address> <roomserver_port> <myport>
```
3. Input your name and click the *User* button.
4. Your can get the list of chatroom groups registered in the Room server by clicking the *List* button.
5. Input the name of the room you want to join and click the *Join* button.
6. To send a message to the chatroom network, you can type the message in the input and click the *Send* button.
