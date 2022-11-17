# Use the build container by default
BUILD_WITH_CONTAINER ?= 1

# sync from common/Makefile.common.mk
FINDFILES=find . \( -path ./common-protos -o -path ./.git -o -path ./out -o -path ./.github -o -path ./licenses -o -path ./vendor \) -prune -o -type f
XARGS = xargs -0 -r

# override target in common/Makefile.common.mk, only check golang and rust codes
lint-copyright-banner:
	@${FINDFILES} \( -name '*.go' -o -name '*.rs' \) \( ! \( -name '*.gen.go' -o -name '*.pb.go' -o -name '*_pb2.py' \) \) -print0 |\
		${XARGS} common/scripts/lint_copyright_banner.sh
