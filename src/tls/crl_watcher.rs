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

use std::sync::Arc;
use tracing::{debug, info};

use crate::drain::DrainWatcher;
use crate::proxy::connection_manager::ConnectionManager;
use crate::tls::crl::CrlManager;

/// CrlWatcher monitors CRL updates and terminates connections with revoked certificates
pub struct CrlWatcher {
    crl_manager: Arc<CrlManager>,
    stop: DrainWatcher,
    connection_manager: ConnectionManager,
}

impl CrlWatcher {
    pub fn new(
        crl_manager: Arc<CrlManager>,
        stop: DrainWatcher,
        connection_manager: ConnectionManager,
    ) -> Self {
        CrlWatcher {
            crl_manager,
            stop,
            connection_manager,
        }
    }

    /// Run the CRL watcher loop
    pub async fn run(self) {
        // Subscribe to CRL changes via watch channel
        let mut crl_changed = self.crl_manager.subscribe_to_changes();

        info!("CRL watcher started");

        debug!("performing initial connection check for revoked certificates");
        self.check_and_close_revoked_connections().await;

        loop {
            tokio::select! {
                _ = self.stop.clone().wait_for_drain() => {
                    info!("CRL watcher shutting down");
                    break;
                }
                _ = crl_changed.changed() => {
                    debug!("CRL changed, checking connections for revoked certificates");
                    self.check_and_close_revoked_connections().await;
                }
            }
        }
    }

    /// Check all active connections and close those with revoked certificates
    async fn check_and_close_revoked_connections(&self) {
        let revoked_serials = self.crl_manager.get_revoked_serials();
        let connections = self.connection_manager.connections();

        debug!(
            "checking {} connection(s) against {} revoked serial(s)",
            connections.len(),
            revoked_serials.len()
        );

        let mut closed_count = 0;

        for conn in connections {
            if let Some(ref serials) = conn.client_cert_serials {
                debug!(
                    "checking connection {} with {} certificate(s)",
                    conn.ctx,
                    serials.len()
                );

                // Check if any certificate in the chain is revoked
                let is_revoked = serials.iter().any(|serial| {
                    let revoked = revoked_serials.contains(serial);
                    if revoked {
                        debug!("  certificate serial {:02x?} is REVOKED", serial);
                    }
                    revoked
                });

                if is_revoked {
                    self.connection_manager.close(&conn).await;
                    info!(
                        "closed connection {} due to certificate revocation",
                        conn.ctx
                    );
                    closed_count += 1;
                }
            }
        }

        if closed_count > 0 {
            info!(
                "closed {} connection(s) due to certificate revocation",
                closed_count
            );
        } else {
            debug!("no connections needed to be closed");
        }
    }
}
