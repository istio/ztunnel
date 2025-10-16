// Copyright Istio Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use crate::dns::resolver::{Answer, Resolver};
use hickory_proto::ProtoErrorKind;
use hickory_proto::op::{Edns, Header, MessageType, OpCode, ResponseCode};
use hickory_proto::rr::Record;
use hickory_resolver::ResolveErrorKind;
use hickory_server::authority::{LookupError, MessageResponse, MessageResponseBuilder};
use hickory_server::server::{Request, RequestHandler, ResponseHandler, ResponseInfo};
use std::sync::Arc;
use tracing::{error, warn};

/// A Trust-DNS [RequestHandler] that proxies all DNS requests.
///
/// A DNS proxy is fundamentally different than an `Authority` in TrustDNS, since the answers may
/// or may not be authoritative based on whether they are served locally or forwarded. It is
/// for this reason that we can't implement the proxy using existing TrustDNS server structures
/// `Catalog` and `Authority`.
// TODO(nmittler): Consider upstreaming this to TrustDNS
pub struct Handler {
    resolver: Arc<dyn Resolver>,
}

impl Handler {
    /// Creates a new request handler for the resolver.
    pub fn new(resolver: Arc<dyn Resolver>) -> Self {
        Self { resolver }
    }

    async fn lookup<R: ResponseHandler>(
        &self,
        request: &Request,
        response_handle: R,
    ) -> ResponseInfo {
        match self.resolver.lookup(request).await {
            Ok(answer) => send_lookup(request, response_handle, answer).await,
            Err(e) => send_lookup_error(request, response_handle, e).await,
        }
    }
}

#[async_trait::async_trait]
impl RequestHandler for Handler {
    async fn handle_request<R: ResponseHandler>(
        &self,
        request: &Request,
        response_handle: R,
    ) -> ResponseInfo {
        match request.message_type() {
            MessageType::Query => match request.op_code() {
                OpCode::Query => self.lookup(request, response_handle).await,
                _ => {
                    warn!("unimplemented op_code: {:?}", request.op_code());
                    send_error(request, response_handle, ResponseCode::NotImp).await
                }
            },
            MessageType::Response => {
                warn!("got a response as a request from id: {}", request.id());
                send_error(request, response_handle, ResponseCode::FormErr).await
            }
        }
    }
}

async fn send_lookup<R: ResponseHandler>(
    request: &Request,
    response_handle: R,
    answer: Answer,
) -> ResponseInfo {
    let mut response_header = Header::response_from_request(request.header());

    // We are the authority here, since we control DNS for known hostnames
    response_header.set_authoritative(answer.is_authoritative());
    response_header.set_recursion_available(true);

    // Create the response builder.
    let mut builder = MessageResponseBuilder::from_message_request(request);

    // Set EDNS if supplied in the request.
    if let Some(edns) = response_edns(request) {
        builder.edns(edns);
    }

    // Build the response.
    let response = builder.build(
        response_header,
        answer.record_iter(),
        None.iter(),
        None.iter(),
        None.iter(),
    );

    // Send the response.
    send_response(response, response_handle).await
}

async fn send_lookup_error<R: ResponseHandler>(
    request: &Request,
    response_handle: R,
    e: LookupError,
) -> ResponseInfo {
    match e {
        LookupError::NameExists => {
            // This is an error, since the hostname was resolved. Just return no records.
            send_empty_response(request, response_handle).await
        }
        LookupError::ResponseCode(code) => send_error(request, response_handle, code).await,
        LookupError::ResolveError(e) => {
            if let ResolveErrorKind::Proto(proto) = e.kind()
                && let ProtoErrorKind::NoRecordsFound { response_code, .. } = proto.kind()
            {
                // Respond with the error code.
                return send_error(request, response_handle, *response_code).await;
            }
            // TODO(nmittler): log?
            send_error(request, response_handle, ResponseCode::ServFail).await
        }
        LookupError::Io(_) => {
            // TODO(nmittler): log?
            send_error(request, response_handle, ResponseCode::ServFail).await
        }
        _ => send_error(request, response_handle, ResponseCode::ServFail).await,
    }
}

/// Sends an error response back to the client.
async fn send_error<R: ResponseHandler>(
    request: &Request,
    response_handle: R,
    code: ResponseCode,
) -> ResponseInfo {
    let response =
        MessageResponseBuilder::from_message_request(request).error_msg(request.header(), code);

    send_response(response, response_handle).await
}

/// Sends an empty response to the [ResponseHandler].
async fn send_empty_response<R: ResponseHandler>(
    request: &Request,
    response_handle: R,
) -> ResponseInfo {
    let empty =
        MessageResponseBuilder::from_message_request(request).build_no_records(*request.header());
    send_response(empty, response_handle).await
}

/// Sends the response to the [ResponseHandler] and handles any errors.
async fn send_response<'a, R: ResponseHandler>(
    response: MessageResponse<
        '_,
        'a,
        impl Iterator<Item = &'a Record> + Send + 'a,
        impl Iterator<Item = &'a Record> + Send + 'a,
        impl Iterator<Item = &'a Record> + Send + 'a,
        impl Iterator<Item = &'a Record> + Send + 'a,
    >,
    mut response_handle: R,
) -> ResponseInfo {
    let result = response_handle.send_response(response).await;

    match result {
        Err(e) => {
            error!("request error: {}", e);
            let mut header = Header::new();
            header.set_response_code(ResponseCode::ServFail);
            header.into()
        }
        Ok(info) => info,
    }
}

/// Creates an appropriate response [Edns], if one was available in the request.
fn response_edns(request: &Request) -> Option<Edns> {
    if let Some(req_edns) = request.edns() {
        let mut resp_edns: Edns = Edns::new();
        resp_edns.set_max_payload(req_edns.max_payload().max(512));
        resp_edns.set_version(req_edns.version());
        resp_edns.set_dnssec_ok(req_edns.flags().dnssec_ok);

        Some(resp_edns)
    } else {
        None
    }
}

#[cfg(test)]
#[cfg(any(unix, target_os = "windows"))]
mod tests {
    use crate::dns::handler::Handler;
    use crate::dns::resolver::{Answer, Resolver};
    use crate::test_helpers::dns::{a, a_request, n, socket_addr};
    use crate::test_helpers::helpers::initialize_telemetry;
    use hickory_proto::op::{Message, MessageType, OpCode, ResponseCode};
    use hickory_proto::rr::{Name, Record, RecordType};
    use hickory_proto::serialize::binary::BinEncoder;
    use hickory_proto::xfer::Protocol;
    use hickory_server::authority::LookupError;
    use hickory_server::authority::MessageResponse;
    use hickory_server::server::{Request, RequestHandler, ResponseHandler, ResponseInfo};
    use std::net::Ipv4Addr;
    use std::sync::Arc;
    use tokio::sync::mpsc;
    use tokio::sync::mpsc::Sender;

    #[tokio::test]
    async fn record_found() {
        initialize_telemetry();

        let p = Handler::new(Arc::new(FakeResolver {}));

        // Lookup a host.
        let req = a_request(n("fake.com"), socket_addr("1.1.1.1:80"), Protocol::Udp);

        let (sender, mut receiver) = mpsc::channel(1);
        let _ = p
            .handle_request(&req, FakeResponseHandler::new(512, sender))
            .await;

        let resp = receiver.recv().await.unwrap();

        // Check basic response header info.
        assert_eq!(req.id(), resp.id());
        assert_eq!(MessageType::Response, resp.message_type());
        assert_eq!(OpCode::Query, resp.op_code());
        assert_eq!(ResponseCode::NoError, resp.response_code());

        // Check flags.
        assert!(!resp.authoritative());
        assert!(!resp.authentic_data());
        assert!(!resp.checking_disabled());
        assert!(resp.recursion_available());
        assert!(resp.recursion_desired());
        assert!(!resp.truncated());

        // Check that we have an answer for the request host.
        let answers = resp.answers();
        assert!(!answers.is_empty());
        assert_eq!(n("fake.com."), *answers[0].name());
        assert_eq!(RecordType::A, answers[0].record_type());

        let expected = a(n("fake.com."), Ipv4Addr::new(127, 0, 0, 1));
        assert_eq!(expected, *answers.iter().next().unwrap());
    }

    struct FakeResolver();

    #[async_trait::async_trait]
    impl Resolver for FakeResolver {
        async fn lookup(&self, request: &Request) -> Result<Answer, LookupError> {
            let name = Name::from(request.request_info()?.query.name().clone());
            let records = vec![a(name, Ipv4Addr::new(127, 0, 0, 1))];
            Ok(Answer::new(records, false))
        }
    }

    #[derive(Clone)]
    pub struct FakeResponseHandler {
        max_size: u16,
        sender: Sender<Message>,
    }

    impl FakeResponseHandler {
        pub fn new(max_size: u16, sender: Sender<Message>) -> Self {
            Self { max_size, sender }
        }
    }

    #[async_trait::async_trait]
    impl ResponseHandler for FakeResponseHandler {
        async fn send_response<'a>(
            &mut self,
            response: MessageResponse<
                '_,
                'a,
                impl Iterator<Item = &'a Record> + Send + 'a,
                impl Iterator<Item = &'a Record> + Send + 'a,
                impl Iterator<Item = &'a Record> + Send + 'a,
                impl Iterator<Item = &'a Record> + Send + 'a,
            >,
        ) -> std::io::Result<ResponseInfo> {
            // Create the encoder.
            let mut buf = Vec::with_capacity(self.max_size as usize);
            let mut encoder = BinEncoder::new(&mut buf);
            encoder.set_max_size(self.max_size);

            // Serialize the response.
            let response_info = response.destructive_emit(&mut encoder)?;

            // Deserialize back into the response message.
            let msg = Message::from_vec(&buf)?;

            // Send the message to the consumer.
            self.sender.send(msg).await.unwrap();

            Ok(response_info)
        }
    }
}
