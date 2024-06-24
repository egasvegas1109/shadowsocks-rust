//! Shadowsocks TCP server

use std::{
    future::Future,
    io::{self, ErrorKind},
    net::SocketAddr,
    sync::{Arc, Mutex},
    time::Duration,
    collections::HashMap,
};

use log::{debug, error, info, trace, warn};
use shadowsocks::{
    crypto::CipherKind,
    net::{AcceptOpts, TcpStream as OutboundTcpStream},
    relay::tcprelay::{utils::copy_encrypted_bidirectional, ProxyServerStream},
    ProxyListener,
    ServerConfig,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream as TokioTcpStream,
    time,
};

use crate::net::{utils::ignore_until_end, MonProxyStream};

use super::context::ServiceContext;

/// TCP server instance
pub struct TcpServer {
    context: Arc<ServiceContext>,
    svr_cfg: ServerConfig,
    listener: ProxyListener,
    connected_ips: Arc<Mutex<HashMap<std::net::IpAddr, u32>>>,
}

impl TcpServer {
    pub(crate) async fn new(
        context: Arc<ServiceContext>,
        svr_cfg: ServerConfig,
        accept_opts: AcceptOpts,
    ) -> io::Result<TcpServer> {
        let listener = ProxyListener::bind_with_opts(context.context(), &svr_cfg, accept_opts).await?;
        Ok(TcpServer {
            context,
            svr_cfg,
            listener,
            connected_ips: Arc::new(Mutex::new(HashMap::new())),
        })
    }

    /// Server's configuration
    pub fn server_config(&self) -> &ServerConfig {
        &self.svr_cfg
    }

    /// Server's listen address
    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.listener.local_addr()
    }

    /// Start server's accept loop
    pub async fn run(self) -> io::Result<()> {
        info!(
            "shadowsocks tcp server listening on {}, inbound address {}",
            self.listener.local_addr().expect("listener.local_addr"),
            self.svr_cfg.addr()
        );

        loop {
            let flow_stat = self.context.flow_stat();

            let (local_stream, peer_addr) = match self
                .listener
                .accept_map(|s| MonProxyStream::from_stream(s, flow_stat))
                .await
            {
                Ok(s) => s,
                Err(err) => {
                    error!("tcp server accept failed with error: {}", err);
                    time::sleep(Duration::from_secs(1)).await;
                    continue;
                }
            };

            if self.context.check_client_blocked(&peer_addr) {
                warn!("access denied from {} by ACL rules", peer_addr);
                continue;
            }

            let client = TcpServerClient {
                context: self.context.clone(),
                method: self.svr_cfg.method(),
                peer_addr,
                stream: local_stream,
                timeout: self.svr_cfg.timeout(),
                connected_ips: self.connected_ips.clone(),
            };

            tokio::spawn(async move {
                if let Err(err) = client.serve().await {
                    debug!("tcp server stream aborted with error: {}", err);
                }
            });
        }
    }
}

#[inline]
async fn timeout_fut<F, R>(duration: Option<Duration>, f: F) -> io::Result<R>
where
    F: Future<Output = io::Result<R>>,
{
    match duration {
        None => f.await,
        Some(d) => match time::timeout(d, f).await {
            Ok(o) => o,
            Err(..) => Err(ErrorKind::TimedOut.into()),
        },
    }
}

struct TcpServerClient {
    context: Arc<ServiceContext>,
    method: CipherKind,
    peer_addr: SocketAddr,
    stream: ProxyServerStream<MonProxyStream<TokioTcpStream>>,
    timeout: Option<Duration>,
    connected_ips: Arc<Mutex<HashMap<std::net::IpAddr, u32>>>,
}

impl TcpServerClient {
    async fn serve(mut self) -> io::Result<()> {
        let target_addr = match timeout_fut(self.timeout, self.stream.handshake()).await {
            Ok(a) => a,
            Err(err) if err.kind() == ErrorKind::UnexpectedEof => {
                debug!(
                    "tcp handshake failed, received EOF before a complete target Address, peer: {}",
                    self.peer_addr
                );
                return Ok(());
            }
            Err(err) if err.kind() == ErrorKind::TimedOut => {
                debug!(
                    "tcp handshake failed, timeout before a complete target Address, peer: {}",
                    self.peer_addr
                );
                return Ok(());
            }
            Err(err) => {
                warn!("tcp handshake failed. peer: {}, {}", self.peer_addr, err);
    
                #[cfg(feature = "aead-cipher-2022")]
                if self.method.is_aead_2022() {
                    let stream = self.stream.into_inner().into_inner();
                    let _ = stream.set_linger(Some(Duration::ZERO));
                    return Ok(());
                }
    
                debug!("tcp silent-drop peer: {}", self.peer_addr);
    
                let mut stream = self.stream.into_inner();
                let res = ignore_until_end(&mut stream).await;
    
                trace!(
                    "tcp silent-drop peer: {} is now closing with result {:?}",
                    self.peer_addr,
                    res
                );
    
                return Ok(());
            }
        };
    
        trace!(
            "accepted tcp client connection {}, establishing tunnel to {}",
            self.peer_addr,
            target_addr
        );
    
        if self.context.check_outbound_blocked(&target_addr).await {
            error!(
                "tcp client {} outbound {} blocked by ACL rules",
                self.peer_addr, target_addr
            );
            return Ok(());
        }

        let mut remote_stream = match timeout_fut(
            self.timeout,
            OutboundTcpStream::connect_remote_with_opts(
                self.context.context_ref(),
                &target_addr,
                self.context.connect_opts_ref(),
            ),
        )
        .await
        {
            Ok(s) => s,
            Err(err) => {
                error!(
                    "tcp tunnel {} -> {} connect failed, error: {}",
                    self.peer_addr, target_addr, err
                );
                return Err(err);
            }
        };

        if self.context.connect_opts_ref().tcp.fastopen {
            let mut buffer = [0u8; 8192];
            match time::timeout(Duration::from_millis(500), self.stream.read(&mut buffer)).await {
                Ok(Ok(0)) => {
                    return Ok(());
                }
                Ok(Ok(n)) => {
                    timeout_fut(self.timeout, remote_stream.write_all(&buffer[..n])).await?;
                }
                Ok(Err(err)) => return Err(err),
                Err(..) => {
                    timeout_fut(self.timeout, remote_stream.write(&[])).await?;
                    trace!(
                        "tcp tunnel {} -> {} sent TFO connect without data",
                        self.peer_addr,
                        target_addr
                    );
                }
            }
        }

        debug!(
            "established tcp tunnel {} <-> {} with {:?}",
            self.peer_addr,
            target_addr,
            self.context.connect_opts_ref()
        );

        let peer_ip = self.peer_addr.ip();
        let mut first_connection = false;
        {
            let mut connected_ips = self.connected_ips.lock().unwrap();
            let counter = connected_ips.entry(peer_ip).or_insert(0);
            if *counter == 0 {
                first_connection = true;
            }
            *counter += 1;
        }
        if first_connection {
            let connected_ips_count = self.connected_ips.lock().unwrap().len();
            println!("Клиент подключен: {}. Всего подключённых уникальных IP: {}", peer_ip, connected_ips_count);
        }

        let result = copy_encrypted_bidirectional(self.method, &mut self.stream, &mut remote_stream).await;
        
        let mut last_disconnection = false;
        {
            let mut connected_ips = self.connected_ips.lock().unwrap();
            if let Some(counter) = connected_ips.get_mut(&peer_ip) {
                *counter -= 1;
                if *counter == 0 {
                    connected_ips.remove(&peer_ip);
                    last_disconnection = true;
                }
            }
        }
        if last_disconnection {
            let connected_ips_count = self.connected_ips.lock().unwrap().len();
            println!("Клиент отключён: {}. Всего подключённых уникальных IP: {}", peer_ip, connected_ips_count);
        }

        match result {
            Ok((rn, wn)) => {
                trace!(
                    "tcp tunnel {} <-> {} closed, L2R {} bytes, R2L {} bytes",
                    self.peer_addr,
                    target_addr,
                    rn,
                    wn
                );
                Ok(())
            }
            Err(err) => {
                trace!(
                    "tcp tunnel {} <-> {} closed with error: {}",
                    self.peer_addr,
                    target_addr,
                    err
                );
                Err(err)
            }
        }
    }
}
