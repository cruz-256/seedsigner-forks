"""Seed Viewer main loop. Refuses to continue when the boot self-test fails."""

from __future__ import annotations

from seedsigner.models.singleton import Singleton
from seedviewer.selftest import run_selftest
from seedviewer.theme import apply_viewer_theme


class Controller(Singleton):
    def start(self) -> None:
        from seedsigner.gui.renderer import Renderer
        from seedviewer.views import SelfTestFailedView, SplashView

        apply_viewer_theme()
        Renderer.get_instance()
        failures = run_selftest()
        view = SelfTestFailedView(failures) if failures else SplashView()
        while True:
            view = view.run()
