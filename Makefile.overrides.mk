# Use the build container by default
BUILD_WITH_CONTAINER ?= 1

# Cannot run root tests in container unless the container is privileged,
# and we cannot/should not run it as privileged by default - so communicate that.
ifeq ($(TEST_MODE), root)
    ifeq ($(BUILD_WITH_CONTAINER), 1)
        $(info ***** NOTE ******)
        $(info TEST_MODE=root and BUILD_WITH_CONTAINER=1)
        $(info If you wish to run tests that require root privilege inside the build container,)
        $(info you must run the container as privileged yourself.)
        $(info Alternatively, set BUILD_WITH_CONTAINER=0 and run the tests as root outside the build container.)
        $(info ***** NOTE ******)
	endif
endif
