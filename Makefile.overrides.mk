# Use the build container by default
BUILD_WITH_CONTAINER ?= 1
# Namespaced tests need sys_admin due to docker being overly restrictive (https://github.com/moby/moby/issues/42441)
# Ironically, this gives the container more privilege than is required without.
DOCKER_RUN_OPTIONS += --privileged
ifeq ($(OS), Linux)
DOCKER_RUN_OPTIONS += -v /fake/path/does/not/exist:/var/run/netns
endif
DOCKER_RUN_OPTIONS += -v /dev/null:/run/xtables.lock
