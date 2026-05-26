//! gRPC reflection types.
//!
//! The reflection protocol itself (gRPC Server Reflection v1) needs
//! a real tonic client and a built protobuf descriptor pool to
//! drive. This module ships the descriptors so the rest of the
//! pipeline can already model what reflection will return; the live
//! reflection client is wired in [`mantis-recon-pipeline`] alongside
//! the existing primitive runner.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GrpcServiceDescriptor {
    /// Fully-qualified service name — e.g. `package.subpackage.Service`.
    pub full_name: String,
    pub methods: Vec<GrpcMethodDescriptor>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GrpcMethodDescriptor {
    pub name: String,
    pub input_type: String,
    pub output_type: String,
    pub client_streaming: bool,
    pub server_streaming: bool,
}

impl GrpcServiceDescriptor {
    /// Short non-package part of the service name.
    pub fn short_name(&self) -> &str {
        self.full_name.rsplit('.').next().unwrap_or(&self.full_name)
    }

    pub fn package(&self) -> Option<&str> {
        let idx = self.full_name.rfind('.')?;
        Some(&self.full_name[..idx])
    }
}

impl GrpcMethodDescriptor {
    /// Build the canonical `/package.Service/Method` path for the
    /// HTTP/2 request line.
    pub fn rpc_path(&self, service: &GrpcServiceDescriptor) -> String {
        format!("/{}/{}", service.full_name, self.name)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn short_name_extracts_last_segment() {
        let s = GrpcServiceDescriptor {
            full_name: "pkg.sub.Greeter".into(),
            methods: vec![],
        };
        assert_eq!(s.short_name(), "Greeter");
    }

    #[test]
    fn package_returns_everything_before_last_dot() {
        let s = GrpcServiceDescriptor {
            full_name: "pkg.sub.Greeter".into(),
            methods: vec![],
        };
        assert_eq!(s.package(), Some("pkg.sub"));
    }

    #[test]
    fn package_returns_none_when_no_package() {
        let s = GrpcServiceDescriptor {
            full_name: "Greeter".into(),
            methods: vec![],
        };
        assert!(s.package().is_none());
        assert_eq!(s.short_name(), "Greeter");
    }

    #[test]
    fn rpc_path_includes_full_name_and_method() {
        let svc = GrpcServiceDescriptor {
            full_name: "pkg.Greeter".into(),
            methods: vec![],
        };
        let m = GrpcMethodDescriptor {
            name: "SayHello".into(),
            input_type: "pkg.HelloRequest".into(),
            output_type: "pkg.HelloReply".into(),
            client_streaming: false,
            server_streaming: false,
        };
        assert_eq!(m.rpc_path(&svc), "/pkg.Greeter/SayHello");
    }

    #[test]
    fn descriptor_round_trips_through_serde() {
        let svc = GrpcServiceDescriptor {
            full_name: "pkg.Greeter".into(),
            methods: vec![GrpcMethodDescriptor {
                name: "SayHello".into(),
                input_type: "pkg.HelloRequest".into(),
                output_type: "pkg.HelloReply".into(),
                client_streaming: false,
                server_streaming: true,
            }],
        };
        let j = serde_json::to_string(&svc).unwrap();
        let back: GrpcServiceDescriptor = serde_json::from_str(&j).unwrap();
        assert_eq!(svc, back);
    }
}
