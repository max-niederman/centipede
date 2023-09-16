# Centipede

Centipede is a work-in-progress multipathing VPN for improving smartphone Internet connection reliability and performance.

## Protocol Overview

Centipede uses two distinct protocols to establish and maintain a VPN connection:

- "Tunnel" protocol: IP packets are encapsulated in UDP messages, encrypted using ChaCha20Poly1305, and sent from N socket addresses on the sender to M socket addresses on the receiver.
  Each tunnel connection is only half-duplex, so two tunnels are needed to form a symmetric VPN connection.
- "Control" protocol: Control messages initiate tunnel connections by coordinating encryption keys and IDs for each socket address.
  To initiate a connection, control messages are sent normally across the public Internet, but after a connection is established they can be sent through the VPN tunnel for improved reliability.
  This is not yet implemented.
