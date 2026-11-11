import pytest

from nids.engine.capture import reset_layer_filter


@pytest.fixture(autouse=True)
def _scapy_layers_unfiltered():
    """main.main() bật lọc tầng Scapy (trạng thái toàn cục); gỡ sau mỗi test để test khác thấy Scapy bóc đủ tầng."""
    yield
    reset_layer_filter()
