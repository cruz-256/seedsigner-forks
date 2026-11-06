"""Seed Viewer main loop. The splash is the first screen; nothing heavy runs first."""

from __future__ import annotations

from seedsigner.models.singleton import Singleton
from seedviewer.theme import apply_viewer_theme


class Controller(Singleton):
    def start(self) -> None:
        from seedsigner.gui.renderer import Renderer
        from seedviewer.views import SplashView

        apply_viewer_theme()
        # Renderer is a ConfigurableSingleton. get_instance() raises until this runs,
        # which used to kill the process before any pixels were sent.
        Renderer.configure_instance()
        view = SplashView()
        while True:
            view = view.run()
