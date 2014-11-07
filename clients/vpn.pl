use strict;
use Fcntl;

use AnyEvent;
use AnyEvent::WebSocket::Client;

sysopen my $tuntap, $ARGV[0], O_RDWR;
die $! if tell($tuntap) < 0;

my $client = AnyEvent::WebSocket::Client->new;

my $connection;
my $tap_event;

$client->connect($ARGV[1])->cb(
	sub {
		$connection = eval { shift->recv };
     		die $@ if $@;

		print "connected to ".$ARGV[1]."\n";

		$tap_event = AnyEvent->io( fh => $tuntap, poll => 'r', cb => sub {
			my $buf ;
			sysread $tuntap, $buf, 1500;
			$connection->send( AnyEvent::WebSocket::Message->new(body =>$buf, opcode => 2 ) ) ; 
		});

		$connection->on(each_message => sub {
			my($connection, $message) = @_;
			syswrite $tuntap, $message->body, length($message->body);
		});
	}
);

AnyEvent->condvar->recv;
