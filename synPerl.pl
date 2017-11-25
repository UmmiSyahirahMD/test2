#program to send out tcp syn packet using raw socket on linux
use Socket;
$src_port = [6666];
$src_host = [192.168.136.129];
$dst_port = [80];
$dst_host = [192.168.197.128];

if(!defined $src_port or !defined $src_host or !defined $dst_port or !defined $dst_host)
{
	#print usage instruction
	print "Usage: $0 <source host> <source port> <dest host> <dest port>\n";
	exit;
}
else
{
	#call the main function
	main();
}
sub main
{
	my $src_host = (gethostbyname($src_host))[4];
	my $dst_host = (gethostbyname($dst_host))[4];
	#when ipproto_raw is used ip_hdrlincl is not needed
	$IPPROTO_RAW = 255;
	socket($sock, AF_INET, SOCK_RAW, $IPPROTO_RAW)
		or die $!;
	#set ip_hdrincl to 1, this is necessary when above protocol is other that ipproto-RAW
	#setsockopt($sock, 0, ip_hdrincl, 1);
	my($packet) = makeheaders($src_host, $src_port, $dst_host, $dst_port);
	my($destination) = pack('Sna4x8', AF_INET, $dst_port, $dst_host);

	while(1)
	{
		send($sock, $packet, 0, $destination)
			or die $!;
	}
}
sub makeheaders 
{
	$IPPROTO_TCP = 6;
	local($src_host, $src_port, $dst_host, $dst_port) = @_;

	my $zero_cksum = 0;
	#lets construct the tcp half
	my $tcp_len = 20;
	my $seq = 13456;
	my $seq_ack = 0;
	my $tcp_doff = "5";
	my $tcp_res = 0;
	my $tcp_doss_res = $tcp_doff . $tcp_res;
	my $tcp_urg = 0;
	my $tcp_ack = 0;
	my $tcp_psh = 0;
	my $tcp_rst = 0;
	my $tcp_syn = 1;
	my $tcp_fin = 0;
	my $null = 0;
	my $tcp_win = 124;

	my $tcp_urg_ptr = 44;
	my $tcp_flags = $null . $null . $tcp_urg . $tcp_ack . $tcp_psh . $tcp_rst . $tcp_syn . $tcp_fin;
	my $tcp_check = 0;

	my $tcp_header = pack('nnNNH2B8nvn', $src_port, $dst_port, $seq, $seq_ack,$tcp_doff_res, $tcp_flags, $tcp_win, $tcp_check, $tcp_urg_ptr);

	my $tcp_pseudo = pacl('a4a4CCn', $src_host, $dest_host, 0, $IPPROTO_TCP,length($tcp_header)) . $tcp_header;
	$tcp_check = &checksum($tcp_pseudo);
	my $tcp_header = pack('nnNNH2B8nvn',$src_port, $dst_port, $seq, $seq_ack, $tcp_doff_res, $tcp_flags, $tcp_win, $tcp_check, $tcp_urg_ptr);

	#ip packet
	my $ip_ver = 4;
	my $ip_len = 5;
	my $ip_ver_len = $ip_ver. $ip_len;
	my $ip_tos = 00;
	my $ip_tot_len = $tcp_len + 20;
	my $ip_frag_id = 19245;
	my $ip_ttl = 25;
	my $ip_proto = $IPPROTO_TCP; #6 FOR TCP
	my $ip_frag_flag = "101";
	my $ip_frag_oset = "0000000000000";
	my $ip_fl_fr = $ip_frag_flag . $ip_frag_oset;

	#ip header
	my $ip_header = pack('H2CnnB16CCna4a4', $ip_ver_len, $ip_tos,
	       	$ip_tot_len,$ip_frag_id,
	  $ip_fl_fr, $ip_ttl, $ip_proto, $zero_cksum, $src_host, $dst_host);

	my $pkt = $ip_header . $tcp_header;
	return $pkt;

	sub checksum
	{
		my($msg)=@_;
		my ($len_msg,$num_short,$chk);
		$len_msg = length($msg);
		$num_short = $len_msg/2;
		$chk =0;

		foreach $short (unpack("S$num_short",$msg))
		{
			$chk += $short;
		}
		$chk += unpack("C", substr($msg, $len_msg-1, 1)) if $len_msg %2;
		$chk = (~((chk>>16) + $chk) & 0xffff);
	}
}	
