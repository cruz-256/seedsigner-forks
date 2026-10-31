"""Which image this tree was built as. The viewer image build rewrites this."""

VARIANT = "signer"


def is_viewer() -> bool:
    return VARIANT == "viewer"
