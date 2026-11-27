// SPDX-License-Identifier: Apache-2.0

use std::{
    collections::{BTreeMap, BTreeSet},
    error::Error,
    path::PathBuf,
    time::Duration,
};

use axum::http::uri::{Authority, PathAndQuery};
use base64::{Engine, prelude::BASE64_STANDARD};
use hyper_util::rt::TokioIo;
use indexmap::IndexSet;
use prost::Message;
use prost_reflect::{DescriptorPool, DynamicMessage, MessageDescriptor, SerializeOptions};
use serde::Serialize;
use serde_json::{Value, json};
use tokio::{io::AsyncReadExt, net::TcpStream, time::timeout};
use tonic::{
    Request, Status,
    codec::{Codec, DecodeBuf, Decoder, EncodeBuf, Encoder},
    transport::{Certificate, Channel, ClientTlsConfig, Endpoint, Identity},
};
use tonic_reflection::pb::v1alpha::{
    ServerReflectionRequest, server_reflection_client::ServerReflectionClient,
    server_reflection_request::MessageRequest, server_reflection_response::MessageResponse,
};
use tower::service_fn;

use crate::upstream::{UpstreamClient, UpstreamError};

const MAX_DESCRIPTOR_BYTES: usize = 1024 * 1024;
const MAX_DESCRIPTOR_COUNT: usize = 1024;
const MAX_DESCRIPTOR_TOTAL: usize = 8 * 1024 * 1024;
const MAX_PEM_BYTES: usize = 1024 * 1024;

pub struct GrpcSettings {
    pub enabled: bool,
    pub admin_enabled: bool,
    pub allow_public_visibility: bool,
    pub timeout: Duration,
    pub max_message_bytes: usize,
    pub min_page_size: u32,
    pub max_page_offset: i64,
    pub include_page_links: bool,
}

impl Default for GrpcSettings {
    fn default() -> Self {
        Self {
            enabled: false,
            admin_enabled: false,
            allow_public_visibility: true,
            timeout: Duration::from_secs(30),
            max_message_bytes: 4 * 1024 * 1024,
            min_page_size: 1,
            max_page_offset: 100_000,
            include_page_links: true,
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum GrpcError {
    #[error("Invalid gRPC target")]
    Target,
    #[error(transparent)]
    Egress(#[from] UpstreamError),
    #[error("Invalid gRPC TLS configuration")]
    Tls,
    #[error("gRPC reflection failed")]
    Reflection,
    #[error("Invalid gRPC descriptors")]
    Descriptors,
    #[error("gRPC call failed")]
    Invocation,
    #[error("gRPC request timed out")]
    Timeout,
}

pub struct GrpcTarget<'a> {
    pub address: &'a str,
    pub tls: bool,
    pub certificate: Option<&'a str>,
    pub key: Option<&'a str>,
}

pub struct GrpcProbe {
    pub service_count: usize,
    _channel: Channel,
}

impl GrpcTarget<'_> {
    pub async fn probe(
        &self,
        upstream: &UpstreamClient,
        deadline: Duration,
    ) -> Result<GrpcProbe, GrpcError> {
        let (channel, discovery) = self.open_reflection(upstream, deadline).await?;
        Ok(GrpcProbe {
            service_count: discovery.services.len(),
            _channel: channel,
        })
    }

    async fn open_reflection(
        &self,
        upstream: &UpstreamClient,
        deadline: Duration,
    ) -> Result<(Channel, Discovery), GrpcError> {
        timeout(deadline, async {
            let channel = self.channel(upstream).await?;
            let discovery = reflect(channel.clone(), deadline).await?;
            Ok((channel, discovery))
        })
        .await
        .map_err(|_| GrpcError::Timeout)?
    }

    pub(crate) fn url(&self) -> Result<String, GrpcError> {
        let lower = self.address.to_ascii_lowercase();
        if ["unix:", "unix-abstract:", "vsock:", "fd:"]
            .iter()
            .any(|scheme| lower.starts_with(scheme))
        {
            return Err(GrpcError::Target);
        }
        let address = ["dns:///", "dns://", "dns:", "ipv4:", "ipv6:"]
            .iter()
            .find_map(|prefix| {
                lower
                    .starts_with(prefix)
                    .then(|| &self.address[prefix.len()..])
            })
            .unwrap_or(self.address);
        if address.contains(['@', '%', '/']) || address.len() > 767 {
            return Err(GrpcError::Target);
        }
        let authority: Authority = address.parse().map_err(|_| GrpcError::Target)?;
        if authority.port_u16().is_none_or(|port| port == 0) || authority.host().is_empty() {
            return Err(GrpcError::Target);
        }
        let scheme = if self.tls { "https" } else { "http" };
        Ok(format!("{scheme}://{authority}"))
    }

    async fn channel(&self, upstream: &UpstreamClient) -> Result<Channel, GrpcError> {
        let origin = self.url()?;
        let addresses = upstream.pinned_addresses(&origin).await?;
        let mut endpoint = Endpoint::from_shared(origin).map_err(|_| GrpcError::Target)?;
        if self.tls {
            let mut tls = ClientTlsConfig::new().with_native_roots();
            if let Some(cert) = self.certificate {
                let cert = read_pem(cert).await?;
                tls = tls.ca_certificate(Certificate::from_pem(&cert));
                if let Some(key) = self.key {
                    tls = tls.identity(Identity::from_pem(cert, read_pem(key).await?));
                }
            } else if self.key.is_some() {
                return Err(GrpcError::Tls);
            }
            endpoint = endpoint.tls_config(tls).map_err(|_| GrpcError::Tls)?;
        }
        endpoint
            .connect_with_connector(service_fn(move |_| {
                let addresses = addresses.clone();
                async move {
                    TcpStream::connect(addresses.as_slice())
                        .await
                        .map(TokioIo::new)
                }
            }))
            .await
            .map_err(|_| GrpcError::Invocation)
    }
}

async fn read_pem(path: &str) -> Result<Vec<u8>, GrpcError> {
    let resolved = tokio::fs::canonicalize(path)
        .await
        .map_err(|_| GrpcError::Tls)?;
    let mut roots = ["/certs", "/etc/ssl", "/etc/pki"]
        .map(PathBuf::from)
        .to_vec();
    roots.push(
        std::env::current_dir()
            .map_err(|_| GrpcError::Tls)?
            .join("certs"),
    );
    let mut allowed = false;
    for root in roots {
        if let Ok(root) = tokio::fs::canonicalize(root).await
            && resolved.starts_with(root)
        {
            allowed = true;
            break;
        }
    }
    if !allowed
        || !tokio::fs::metadata(&resolved)
            .await
            .map_err(|_| GrpcError::Tls)?
            .is_file()
    {
        return Err(GrpcError::Tls);
    }
    let file = tokio::fs::File::open(&resolved)
        .await
        .map_err(|_| GrpcError::Tls)?;
    if !file.metadata().await.map_err(|_| GrpcError::Tls)?.is_file() {
        return Err(GrpcError::Tls);
    }
    let mut bytes = Vec::new();
    file.take((MAX_PEM_BYTES + 1) as u64)
        .read_to_end(&mut bytes)
        .await
        .map_err(|_| GrpcError::Tls)?;
    if bytes.len() > MAX_PEM_BYTES {
        return Err(GrpcError::Tls);
    }
    Ok(bytes)
}

#[derive(Serialize)]
pub(crate) struct ReflectedMethod {
    pub(crate) name: String,
    pub(crate) input_type: String,
    pub(crate) output_type: String,
    pub(crate) client_streaming: bool,
    pub(crate) server_streaming: bool,
}

#[derive(Serialize)]
pub(crate) struct ReflectedService {
    pub(crate) name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) package: Option<String>,
    pub(crate) methods: Vec<ReflectedMethod>,
}

pub(crate) struct Discovery {
    pub(crate) services: BTreeMap<String, ReflectedService>,
    blobs: Vec<Vec<u8>>,
}

impl Discovery {
    pub(crate) fn stored(&self) -> Value {
        let (mut data, blobs) = (
            serde_json::to_value(&self.services).expect("reflected metadata serializes"),
            self.blobs
                .iter()
                .map(|blob| BASE64_STANDARD.encode(blob))
                .collect::<Vec<_>>(),
        );
        data["_file_descriptors"] = json!(blobs);
        data
    }
}

pub(crate) async fn discover(
    upstream: &UpstreamClient,
    target: &GrpcTarget<'_>,
    deadline: Duration,
) -> Result<Discovery, GrpcError> {
    let (_, discovery) = target.open_reflection(upstream, deadline).await?;
    Ok(discovery)
}

async fn reflect(channel: Channel, deadline: Duration) -> Result<Discovery, GrpcError> {
    let mut client = ServerReflectionClient::new(channel)
        .max_decoding_message_size(MAX_DESCRIPTOR_TOTAL + 64 * 1024);
    let MessageResponse::ListServicesResponse(list) = reflection_request(
        &mut client,
        MessageRequest::ListServices(String::new()),
        deadline,
    )
    .await?
    else {
        return Err(GrpcError::Reflection);
    };
    if list.service.len() > MAX_DESCRIPTOR_COUNT {
        return Err(GrpcError::Descriptors);
    }
    let names = list
        .service
        .into_iter()
        .map(|service| service.name)
        .filter(|name| !name.contains("ServerReflection"))
        .collect::<BTreeSet<_>>();
    let mut blobs = IndexSet::new();
    let mut size = 0;
    let mut services = BTreeMap::new();
    for name in &names {
        let files = match reflection_request(
            &mut client,
            MessageRequest::FileContainingSymbol(name.clone()),
            deadline,
        )
        .await
        {
            Ok(MessageResponse::FileDescriptorResponse(files)) => files,
            Ok(_) => continue,
            Err(GrpcError::Timeout) => return Err(GrpcError::Timeout),
            Err(error) => {
                tracing::debug!(reason = %error, "gRPC descriptor request failed");
                services.insert(
                    name.clone(),
                    ReflectedService {
                        name: name.clone(),
                        package: None,
                        methods: Vec::new(),
                    },
                );
                continue;
            }
        };
        for blob in files.file_descriptor_proto {
            let length = blob.len();
            if length > MAX_DESCRIPTOR_BYTES {
                return Err(GrpcError::Descriptors);
            }
            if blobs.insert(blob) {
                size += length;
                if size > MAX_DESCRIPTOR_TOTAL || blobs.len() > MAX_DESCRIPTOR_COUNT {
                    return Err(GrpcError::Descriptors);
                }
            }
        }
    }
    let blobs = blobs.into_iter().collect::<Vec<_>>();
    let pool = descriptor_pool(&blobs)?;
    services.extend(
        pool.services()
            .filter(|service| names.contains(service.full_name()))
            .map(|service| {
                let name = service.full_name().to_owned();
                let result = ReflectedService {
                    name: name.clone(),
                    package: Some(service.package_name().to_owned()),
                    methods: service
                        .methods()
                        .map(|method| ReflectedMethod {
                            name: method.name().to_owned(),
                            input_type: format!(".{}", method.input().full_name()),
                            output_type: format!(".{}", method.output().full_name()),
                            client_streaming: method.is_client_streaming(),
                            server_streaming: method.is_server_streaming(),
                        })
                        .collect(),
                };
                (name, result)
            }),
    );
    Ok(Discovery { services, blobs })
}

async fn reflection_request(
    client: &mut ServerReflectionClient<Channel>,
    request: MessageRequest,
    deadline: Duration,
) -> Result<MessageResponse, GrpcError> {
    let mut request = Request::new(futures_util::stream::iter([ServerReflectionRequest {
        host: String::new(),
        message_request: Some(request),
    }]));
    request.set_timeout(deadline);
    client
        .server_reflection_info(request)
        .await
        .map_err(map_status)?
        .into_inner()
        .message()
        .await
        .map_err(map_status)?
        .and_then(|response| response.message_response)
        .ok_or(GrpcError::Reflection)
}

fn descriptor_pool(blobs: &[Vec<u8>]) -> Result<DescriptorPool, GrpcError> {
    let mut set = Vec::new();
    for file in blobs {
        prost::encoding::bytes::encode(1, file, &mut set);
    }
    DescriptorPool::decode(set.as_slice()).map_err(|_| GrpcError::Descriptors)
}

fn load_descriptors(stored: &Value) -> Result<Vec<Vec<u8>>, GrpcError> {
    let Some(values) = stored.get("_file_descriptors").and_then(Value::as_array) else {
        return Ok(Vec::new());
    };
    let mut remaining = MAX_DESCRIPTOR_TOTAL;
    if values.len() > MAX_DESCRIPTOR_COUNT {
        return Err(GrpcError::Descriptors);
    }
    values
        .iter()
        .map(|value| {
            let encoded = value
                .as_str()
                .filter(|value| value.len() <= MAX_DESCRIPTOR_BYTES.div_ceil(3) * 4)
                .ok_or(GrpcError::Descriptors)?;
            let decoded = BASE64_STANDARD
                .decode(encoded)
                .map_err(|_| GrpcError::Descriptors)?;
            remaining = remaining
                .checked_sub(decoded.len())
                .ok_or(GrpcError::Descriptors)?;
            if decoded.len() > MAX_DESCRIPTOR_BYTES {
                return Err(GrpcError::Descriptors);
            }
            Ok(decoded)
        })
        .collect()
}

pub(crate) async fn invoke(
    upstream: &UpstreamClient,
    target: &GrpcTarget<'_>,
    stored: &Value,
    full_name: &str,
    arguments: Value,
    deadline: Duration,
    limit: usize,
) -> Result<Value, GrpcError> {
    timeout(deadline, async {
        let channel = target.channel(upstream).await?;
        let blobs = load_descriptors(stored)?;
        let pool = if blobs.is_empty() {
            descriptor_pool(&reflect(channel.clone(), deadline).await?.blobs)?
        } else {
            descriptor_pool(&blobs)?
        };
        let (service, method) = full_name.rsplit_once('.').ok_or(GrpcError::Invocation)?;
        let method = pool
            .get_service_by_name(service)
            .and_then(|descriptor| {
                descriptor
                    .methods()
                    .find(|candidate| candidate.name() == method)
            })
            .filter(|method| !method.is_client_streaming() && !method.is_server_streaming())
            .ok_or(GrpcError::Invocation)?;
        let message = DynamicMessage::deserialize(method.input(), arguments)
            .map_err(|_| GrpcError::Invocation)?;
        let path: PathAndQuery = format!("/{service}/{}", method.name())
            .parse()
            .map_err(|_| GrpcError::Invocation)?;
        let mut client = tonic::client::Grpc::new(channel)
            .max_decoding_message_size(limit)
            .max_encoding_message_size(limit);
        client.ready().await.map_err(|_| GrpcError::Invocation)?;
        let mut request = Request::new(message);
        request.set_timeout(deadline);
        let response = client
            .unary(request, path, DynamicCodec(method.output()))
            .await
            .map_err(map_status)?
            .into_inner();
        let options = SerializeOptions::new()
            .use_proto_field_name(true)
            .skip_default_fields(false);
        response
            .serialize_with_options(serde_json::value::Serializer, &options)
            .map_err(|_| GrpcError::Invocation)
    })
    .await
    .map_err(|_| GrpcError::Timeout)?
}

fn map_status(status: Status) -> GrpcError {
    let local_timeout = std::iter::successors(status.source(), |&error| error.source())
        .any(|error| error.is::<tonic::TimeoutExpired>());
    if local_timeout || status.code() == tonic::Code::DeadlineExceeded {
        GrpcError::Timeout
    } else {
        GrpcError::Invocation
    }
}

struct DynamicCodec(MessageDescriptor);
struct DynamicEncoder;
struct DynamicDecoder(MessageDescriptor);

impl Codec for DynamicCodec {
    type Encode = DynamicMessage;
    type Decode = DynamicMessage;
    type Encoder = DynamicEncoder;
    type Decoder = DynamicDecoder;

    fn encoder(&mut self) -> Self::Encoder {
        DynamicEncoder
    }

    fn decoder(&mut self) -> Self::Decoder {
        DynamicDecoder(self.0.clone())
    }
}

impl Encoder for DynamicEncoder {
    type Item = DynamicMessage;
    type Error = Status;

    fn encode(&mut self, item: Self::Item, buffer: &mut EncodeBuf<'_>) -> Result<(), Self::Error> {
        item.encode(buffer)
            .map_err(|_| Status::internal("Cannot encode protobuf request"))
    }
}

impl Decoder for DynamicDecoder {
    type Item = DynamicMessage;
    type Error = Status;

    fn decode(&mut self, buffer: &mut DecodeBuf<'_>) -> Result<Option<Self::Item>, Self::Error> {
        DynamicMessage::decode(self.0.clone(), buffer)
            .map(Some)
            .map_err(|_| Status::internal("Cannot decode protobuf response"))
    }
}
