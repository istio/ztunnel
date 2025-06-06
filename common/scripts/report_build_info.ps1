# Get the current Git revision
$BUILD_GIT_REVISION = git rev-parse HEAD 2>$null
if ($BUILD_GIT_REVISION) {
    # Check if there are uncommitted changes in the working directory
    if (-not $env:IGNORE_DIRTY_TREE -and (git status --porcelain 2>$null)) {
        $BUILD_GIT_REVISION = "$BUILD_GIT_REVISION-dirty"
    }
} else {
    $BUILD_GIT_REVISION = "unknown"
}

# Check the status of the working tree
$tree_status = "Clean"
if (-not $env:IGNORE_DIRTY_TREE -and -not (git diff-index --quiet HEAD --)) {
    $tree_status = "Modified"
}

# Get the Git tag description
$GIT_DESCRIBE_TAG = git describe --tags --always

# Set the Docker hub, default to "docker.io/istio" if HUB is not set
$HUB = if ($env:HUB) { $env:HUB } else { "docker.io/istio" }

$BUILD_OS = if ($env:OS -eq "Windows_NT") { "windows" } else { "" }
$BUILD_ARCH = if ($env:PROCESSOR_ARCHITECTURE -eq "AMD64") { "amd64fre" } else { "" }

# Output version information used by common/scripts/gobuild.sh
Write-Output "istio.io/istio/pkg/version.buildVersion=$($env:VERSION -or $BUILD_GIT_REVISION)"
Write-Output "istio.io/istio/pkg/version.buildGitRevision=$BUILD_GIT_REVISION"
Write-Output "istio.io/istio/pkg/version.buildStatus=$tree_status"
Write-Output "istio.io/istio/pkg/version.buildTag=$GIT_DESCRIBE_TAG"
Write-Output "istio.io/istio/pkg/version.buildHub=$HUB"
Write-Output "istio.io/istio/pkg/version.buildOS=$BUILD_OS"
Write-Output "istio.io/istio/pkg/version.buildArch=$BUILD_ARCH"