"""Provide a stand-in for RPi.GPIO so unit tests can import the UI modules."""
import sys
from unittest.mock import MagicMock


if "RPi" not in sys.modules:
    gpio = MagicMock()
    gpio.RPI_INFO = {"P1_REVISION": 3}
    gpio.IN = 1
    gpio.PUD_UP = 1
    gpio.LOW = 0
    gpio.HIGH = 1
    gpio.BOARD = 1
    rpi = MagicMock()
    rpi.GPIO = gpio
    sys.modules["RPi"] = rpi
    sys.modules["RPi.GPIO"] = gpio
