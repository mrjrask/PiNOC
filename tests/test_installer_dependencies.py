from pathlib import Path


INSTALLER = Path(__file__).parents[1] / "install.sh"


def test_installer_includes_freetype_runtime_for_pillow_fonts():
    script = INSTALLER.read_text(encoding="utf-8")
    dependency_block = script.split("APT_PACKAGES=(", 1)[1].split(")", 1)[0]

    assert "libfreetype6" in dependency_block.split()
    assert "ImageFont.truetype" in script
