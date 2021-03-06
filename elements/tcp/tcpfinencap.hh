/*
 * tcpfinencap.{cc,hh} -- encapsulates packet with a TCP header with FIN set
 * Rafael Laufer, Massimo Gallo
 *
 * Copyright (c) 2017 Nokia Bell Labs
 *
 * Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:
 * 
 * 1. Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer 
 *    in the documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the copyright holder nor the names of its contributors may be used to endorse or promote products derived
 *    from this software without specific prior written permission.
 *
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED
 * TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR
 * CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
 * PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
 * LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE,
 * EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 *
 */


#ifndef CLICK_TCPFINENCAP_HH
#define CLICK_TCPFINENCAP_HH
#include <click/element.hh>
CLICK_DECLS

/*
=c

TCPFinEncap

=s tcp

encapsulates packets with a TCP header with the FIN flag set

=d

A TCP header is prepended to the packet and the FIN flag is set. The header
information (e.g., ports, SEQ, ACK, WND) is filled using the TCP state in the
packet annotations. If the OPLEN annotation is set, it is used to properly set
the offset field in the TCP header. The ACK flag is always set.

The StripTCPHeader element can be used by the receiver to get rid of the TCP
header.

=e

Encapsulates packets with a TCP header with the FIN flag set. 

    ... -> TCPAckOptionsEncap
        -> TCPFinEncap
        -> TCPIPEncap
        -> ...

=a TCPSynEncap, TCPAckEncap, TCPAckOptionsEncap */

class TCPFinEncap final : public Element { public:

	TCPFinEncap() CLICK_COLD;

	const char *class_name() const		{ return "TCPFinEncap"; }
	const char *port_count() const		{ return PORTS_1_1; }
	const char *processing() const		{ return AGNOSTIC; }

	Packet *smaction(Packet *);
	void push(int, Packet *) final;
	Packet *pull(int);

};

CLICK_ENDDECLS
#endif
