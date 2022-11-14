use std::env;
use std::fmt;
use std::fmt::{Display, Formatter};
use std::string::String;

const BUILD_VERSION: &str = env!("ZTUNNEL_BUILD_buildVersion");
const BUILD_GIT_REVISION: &str = env!("ZTUNNEL_BUILD_buildGitRevision");
const BUILD_STATUS: &str = env!("ZTUNNEL_BUILD_buildStatus");
const BUILD_TAG: &str = env!("ZTUNNEL_BUILD_buildTag");
const BUILD_RUST_VERSION: &str = env!("ZTUNNEL_BUILD_RUSTC_VERSION");

#[derive(Clone, Debug, Default)]
pub struct BuildInfo {
    version: String,
    git_revision: String,
    rust_version: String,
    build_status: String,
    git_tag: String,
}

impl BuildInfo {
    pub fn new() -> Self {
        BuildInfo {
            version: BUILD_VERSION.to_string(),
            git_revision: BUILD_GIT_REVISION.to_string(),
            rust_version: BUILD_RUST_VERSION.to_string(),
            build_status: BUILD_STATUS.to_string(),
            git_tag: BUILD_TAG.to_string(),
        }
    }
}

impl Display for BuildInfo {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "version.BuildInfo{{Version:\"{}\", GitRevision:\"{}\", RustVersion:\"{}\", BuildStatus:\"{}\", GitTag:\"{}\"}}",
        self.version, self.git_revision, self.rust_version, self.build_status, self.git_tag)
    }
}
