use std::future::Future;
use std::time::Duration;

use bytes::Bytes;
use futures::pin_mut;
use futures_util::future;
use futures_util::future::Either;
use http_body_util::Empty;
use hyper::body::Incoming;
use hyper::client::conn::http2;
use hyper::http::{Request, Response};
use hyper_util::client::pool;
use hyper_util::client::pool::{Pool as HyperPool, Poolable, Pooled, Reservation};
use tracing::debug;

use crate::identity::Identity;
use crate::proxy::Error;

#[derive(Clone)]
pub struct Pool {
    pool: HyperPool<Client, Key>,
}

impl Pool {
    pub fn new() -> Pool {
        Self {
            pool: HyperPool::new(
                hyper_util::client::pool::Config {
                    idle_timeout: Some(Duration::from_secs(90)),
                    max_idle_per_host: std::usize::MAX,
                },
                &hyper_util::Exec::Default,
            ),
        }
    }
}

pub struct TokioExec;
impl<F> hyper::rt::Executor<F> for TokioExec
where
    F: std::future::Future + Send + 'static,
    F::Output: Send + 'static,
{
    fn execute(&self, fut: F) {
        tokio::spawn(fut);
    }
}

#[derive(Debug, Clone)]
struct Client(http2::SendRequest<Empty<Bytes>>);

impl Poolable for Client {
    fn is_open(&self) -> bool {
        // self.0.is_ready()
        true
    }

    fn reserve(self) -> Reservation<Self> {
        let b = self.clone();
        let a = self;
        Reservation::Shared(a, b)
    }

    fn can_share(&self) -> bool {
        true // http2 always shares
    }
}

#[derive(PartialEq, Eq, Hash, Clone, Debug)]
pub struct Key {
    pub src: Identity,
    pub dst: Identity,
}

#[derive(Debug)]
pub struct Connection(Pooled<Client, Key>);

impl Connection {
    pub fn send_request(
        &mut self,
        req: Request<Empty<Bytes>>,
    ) -> impl Future<Output = hyper::Result<Response<Incoming>>> {
        self.0 .0.send_request(req)
    }
}

impl Pool {
    pub async fn connect<F>(&self, key: Key, connect: F) -> Result<Connection, Error>
    where
        F: Future<Output = Result<http2::SendRequest<Empty<Bytes>>, Error>>,
    {
        let reuse_connection = self.pool.checkout(key.clone());

        let connect_pool = async {
            let ver = hyper_util::client::pool::Ver::Http2;
            let Some(connecting) = self.pool.connecting(&key, ver) else {
                // TODO: this is obscure, make it more explicit
                return Err(Error::Dropped)
            };
            let pc = Client(connect.await?);
            let pooled = self.pool.pooled(connecting, pc);
            Ok::<_, Error>(pooled)
        };
        pin_mut!(connect_pool);
        let request_sender: Pooled<Client, _> =
            match future::select(reuse_connection, connect_pool).await {
                Either::Left((Ok(conn), _)) => {
                    debug!(?key, "fetched existing connection");
                    conn
                }
                Either::Left((Err(err), connecting)) => match err {
                    pool::Error::CheckedOutClosedValue => connecting.await?,
                    _ => return Err(Error::Dropped),
                },
                // Connect won, checkout can just be dropped.
                Either::Right((Ok(request_sender), _checkout)) => {
                    debug!(?key, "established new connection");
                    request_sender
                }
                // Connect won, checkout can just be dropped.
                Either::Right((Err(err), checkout)) => match err {
                    Error::Dropped => checkout.await?,
                    _ => return Err(Error::Dropped),
                },
            };

        Ok(Connection(request_sender))
    }
}
#[cfg(test)]
mod test {
    use std::convert::Infallible;
    use std::net::SocketAddr;

    use hyper::body::Incoming;
    use hyper::service::service_fn;
    use hyper::{Request, Response};
    use tokio::net::{TcpListener, TcpStream};
    use tracing::{error, info};

    use super::*;

    #[tokio::test]
    async fn test_pool() {
        // We'll bind to 127.0.0.1:3000
        let addr = SocketAddr::from(([127, 0, 0, 1], 0));
        async fn hello_world(req: Request<Incoming>) -> Result<Response<Empty<Bytes>>, Infallible> {
            info!("got req {req:?}");
            Ok(Response::builder().status(200).body(Empty::new()).unwrap())
        }

        // We create a TcpListener and bind it to 127.0.0.1:3000
        let listener = TcpListener::bind(addr).await.unwrap();

        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            // We start a loop to continuously accept incoming connections
            loop {
                let (stream, _) = listener.accept().await.unwrap();

                // Spawn a tokio task to serve multiple connections concurrently
                tokio::task::spawn(async move {
                    // Finally, we bind the incoming connection to our `hello` service
                    if let Err(err) = crate::hyper_util::http2_server()
                        .serve_connection(stream, service_fn(hello_world))
                        .await
                    {
                        println!("Error serving connection: {:?}", err);
                    }
                });
            }
        });
        let pool = Pool::new();
        let key = Key {
            src: Identity::default(),
            dst: Identity::default(),
        };
        let connect = || async {
            let builder = http2::Builder::new(TokioExec);

            let tcp_stream = TcpStream::connect(addr).await?;
            let (request_sender, connection) = builder.handshake(tcp_stream).await?;
            // spawn a task to poll the connection and drive the HTTP state
            tokio::spawn(async move {
                if let Err(e) = connection.await {
                    error!("Error in connection handshake: {:?}", e);
                }
            });
            Ok(request_sender)
        };
        let req = || {
            hyper::Request::builder()
                .uri(format!("http://{addr}"))
                .method(hyper::Method::GET)
                .version(hyper::Version::HTTP_2)
                .body(Empty::<Bytes>::new())
                .unwrap()
        };
        let mut c1 = pool.connect(key.clone(), connect()).await.unwrap();
        let mut c2 = pool
            .connect(key, async { unreachable!("should use pooled connection") })
            .await
            .unwrap();
        assert_eq!(c1.send_request(req()).await.unwrap().status(), 200);
        assert_eq!(c1.send_request(req()).await.unwrap().status(), 200);
        assert_eq!(c2.send_request(req()).await.unwrap().status(), 200);
    }
}
