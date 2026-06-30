//! UDP + TCP DNS listeners.
//!
//! Both transports share one [`Resolver`]. UDP answers are capped at 512 bytes (the classic
//! non-EDNS limit): an over-long answer is returned truncated with the TC bit set, prompting the
//! client to retry over TCP, where there is no size cap (a 2-byte length prefix frames each
//! message). Each datagram / connection is handled on its own spawned task, so a slow client never
//! stalls another.
//!
//! IMPORTANT: this binds the address from [`Config::dns_addr`], which defaults to the ALT port
//! `:5353` — NEVER the privileged `:53`. Lodestar is being stood up ALONGSIDE the live resolver and
//! must not touch port 53 or the live wildcard resolution. Go-live (repointing the registrar NS to
//! this server) is a deliberate, human step, out of scope for the service itself.

use std::sync::Arc;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, UdpSocket};

use crate::dns::resolver::Resolver;
use crate::dns::{
    build_response, header_only_response, parse_query, Lookup, CLASS_IN, RCODE_FORMERR,
    RCODE_NOTIMP,
};

/// Largest UDP answer we send without EDNS; beyond this we set TC and let the client retry on TCP.
const UDP_MAX: usize = 512;

/// Bind the UDP + TCP listeners on `addr` and spawn their accept loops. Returns once both are bound
/// (binding errors are surfaced to the caller); the loops then run for the life of the process.
pub async fn serve(resolver: Resolver, addr: &str) -> std::io::Result<()> {
    let udp = Arc::new(UdpSocket::bind(addr).await?);
    let tcp = TcpListener::bind(addr).await?;
    tracing::info!(%addr, "DNS server listening (UDP + TCP, ALT port — never :53)");

    tokio::spawn(udp_loop(udp, resolver.clone()));
    tokio::spawn(tcp_loop(tcp, resolver));
    Ok(())
}

/// Receive datagrams forever, answering each on a spawned task.
async fn udp_loop(sock: Arc<UdpSocket>, resolver: Resolver) {
    let mut buf = vec![0u8; 4096];
    loop {
        let (n, peer) = match sock.recv_from(&mut buf).await {
            Ok(v) => v,
            Err(e) => {
                tracing::warn!(error = %e, "udp recv_from failed");
                continue;
            }
        };
        let query = buf[..n].to_vec();
        let resolver = resolver.clone();
        let sock = sock.clone();
        tokio::spawn(async move {
            let resp = handle_query(&resolver, &query, true);
            if let Err(e) = sock.send_to(&resp, peer).await {
                tracing::warn!(error = %e, "udp send_to failed");
            }
        });
    }
}

/// Accept TCP connections forever, serving length-prefixed messages on each until it closes.
async fn tcp_loop(listener: TcpListener, resolver: Resolver) {
    loop {
        let (mut stream, _peer) = match listener.accept().await {
            Ok(v) => v,
            Err(e) => {
                tracing::warn!(error = %e, "tcp accept failed");
                continue;
            }
        };
        let resolver = resolver.clone();
        tokio::spawn(async move {
            loop {
                let mut len_buf = [0u8; 2];
                if stream.read_exact(&mut len_buf).await.is_err() {
                    break; // clean EOF or read error -> connection done
                }
                let len = u16::from_be_bytes(len_buf) as usize;
                let mut msg = vec![0u8; len];
                if stream.read_exact(&mut msg).await.is_err() {
                    break;
                }
                let resp = handle_query(&resolver, &msg, false);
                let mut framed = Vec::with_capacity(2 + resp.len());
                framed.extend_from_slice(&(resp.len() as u16).to_be_bytes());
                framed.extend_from_slice(&resp);
                if stream.write_all(&framed).await.is_err() {
                    break;
                }
            }
        });
    }
}

/// Turn one raw request message into a wire response. `udp` enables the 512-byte truncation rule.
fn handle_query(resolver: &Resolver, buf: &[u8], udp: bool) -> Vec<u8> {
    let Some(query) = parse_query(buf) else {
        // Best-effort id from the first two bytes; otherwise 0.
        let id = if buf.len() >= 2 {
            u16::from_be_bytes([buf[0], buf[1]])
        } else {
            0
        };
        return header_only_response(id, 0, false, RCODE_FORMERR);
    };

    // We implement only the standard QUERY opcode and class IN.
    if query.opcode != 0 {
        return header_only_response(query.id, query.opcode, query.rd, RCODE_NOTIMP);
    }
    if query.qname.is_empty() {
        return header_only_response(query.id, query.opcode, query.rd, RCODE_FORMERR);
    }
    if query.qclass != CLASS_IN {
        return header_only_response(query.id, query.opcode, query.rd, RCODE_NOTIMP);
    }

    let lookup = resolver.lookup(&query.qname, query.qtype);
    tracing::debug!(
        qname = %query.qname,
        qtype = query.qtype,
        rcode = lookup.rcode,
        answers = lookup.answers.len(),
        "dns query"
    );
    let resp = build_response(&query, &lookup);

    if udp && resp.len() > UDP_MAX {
        // Re-emit header-only (question echoed) with the TC bit set so the client retries on TCP.
        let mut truncated = build_response(
            &query,
            &Lookup {
                rcode: lookup.rcode,
                aa: lookup.aa,
                answers: Vec::new(),
                authority: Vec::new(),
            },
        );
        if truncated.len() >= 4 {
            let flags = u16::from_be_bytes([truncated[2], truncated[3]]) | 0x0200; // TC
            truncated[2..4].copy_from_slice(&flags.to_be_bytes());
        }
        return truncated;
    }
    resp
}
