"""Save an installation window directly, without Finder/AppleScript automation."""

from pathlib import Path
import sys

from ds_store import DSStore
from mac_alias import Alias


def write_layout(mount):
    background = mount / ".background.tiff"
    with DSStore.open(str(mount / ".DS_Store"), "w+") as store:
        store["."]["vSrn"] = ("long", 1)
        store["."]["icvl"] = ("type", b"icnv")
        store["."]["vstl"] = ("type", b"icnv")
        store["."]["bwsp"] = {
            # Include title/path bars so the complete 480-point artwork fits.
            "WindowBounds": "{{160, 160}, {760, 540}}",
            "ShowToolbar": False, "ShowSidebar": False,
            "ShowStatusBar": False, "ShowPathbar": False, "ShowTabView": False,
            "ContainerShowSidebar": False, "PreviewPaneVisibility": False,
            "SidebarWidth": 0,
        }
        store["."]["icvp"] = {
            "viewOptionsVersion": 1, "backgroundType": 2,
            "backgroundColorRed": 1.0, "backgroundColorGreen": 1.0, "backgroundColorBlue": 1.0,
            "backgroundImageAlias": Alias.for_file(str(background)).to_bytes(),
            "gridOffsetX": 0.0, "gridOffsetY": 0.0, "gridSpacing": 80.0,
            "arrangeBy": "none", "showIconPreview": False, "showItemInfo": False,
            "labelOnBottom": True, "textSize": 13.0, "iconSize": 100.0,
            "scrollPositionX": 0.0, "scrollPositionY": 0.0,
        }
        store["Easy Analyzer.app"]["Iloc"] = (200, 284)
        store["Applications"]["Iloc"] = (560, 284)


if __name__ == "__main__":
    if len(sys.argv) != 2:
        raise SystemExit("Usage: write_dmg_layout.py <mounted image>")
    write_layout(Path(sys.argv[1]).resolve())
