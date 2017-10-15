
#!/usr/bin/perl
#tcpserver.pl

use IO::Socket::INET;

#flush after every write
$| =1;
my ($socket, $client_socket);
my($peer_address,$peer_port);

#creating object interface of IO::Socket::INET modules which internally does
#socket creation, binding and listening a the specific port address.
$socket = new IO::Socket::INET (
	PeerHost => '192.168.48.136',
	LocalPort => '5000',
	Proto => 'tcp',
	Listen => 5,
	Reuse => 1
) or die "Error in socket creation : $!\n";

print "SERVER waitiing for client connection p=on port 5000";

while (1)
{
	#waiting for new client connection.
	$client_socket = $socket->accept();

	#get the host and port number of newly connected client.
	$peer_address = $client_socket->peerhost();
	$peer_port = $client_socket->peerport();

	print "accepted new client connection from : $peer_address, $peer_port\n";
	
	#write operation on the newly accepted client
	$data = "Data from SERVER\n";
	print $client_socket "$data\n";
	#we can also send data through IO::Socket::INET module,
	# $client_socket->send($data);
	
	#read operation on the newly accepted client
	$data = <$client_socket>;
	#we can also read from socket through recv() in IO::Socket::INET
	#$client_socket->recv($data,1024);
	print "received from client :\t$data\n";
}
$socket->close();


