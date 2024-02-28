# Use the build container by default
BUILD_WITH_CONTAINER ?= 1

# Cannot run root tests in container unless the container is privileged,
# and we cannot/should not run it as privileged by default - so communicate that.
ifeq ($(TEST_MODE), root)
    ifeq ($(BUILD_WITH_CONTAINER), 1)
        $(info ***** NOTE ******)
        $(info TEST_MODE=root and BUILD_WITH_CONTAINER=1)
        $(info Running tests as root inside a build container requires running the container in privileged mode)
        $(info If you are uncomfortable with this or your environment does not allow priviledged containers,)
        $(info set BUILD_WITH_CONTAINER=0 and run the tests as root outside the build container.)
        $(info ***** NOTE ******)
		DOCKER_RUN_OPTIONS += --privileged
		UID = 0
	endif
endif
