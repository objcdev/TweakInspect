"""
Install TweakInspect's Hopper script, including the required dependencies.

Dependencies must already be installed in the current python environment.
"""

import shutil
from pathlib import Path

import capstone
import more_itertools
import pkg_resources
import strongarm
import strongarm_dataflow
import unix_ar

import tweakinspect

HOPPER_SCRIPTS_PATH = Path.home() / "Library/Application Support/Hopper/Scripts/"
HOPPER_TWEAK_INSPECT_SCRIPT = Path("hopper.py").resolve()

# Symlink the main script to Hopper's folder
try:
    (HOPPER_SCRIPTS_PATH / "inspect_hooks.py").symlink_to(HOPPER_TWEAK_INSPECT_SCRIPT)
except FileExistsError:
    pass

# Symlink dependencies needed by TweakInspect into Hopper's script folder
modules_to_copy = [tweakinspect, unix_ar, strongarm, capstone, pkg_resources, more_itertools, strongarm_dataflow]
for module in modules_to_copy:
    module_import_path = Path(module.__file__)

    if "site-packages/" in module_import_path.as_posix():
        module_path_components = module_import_path.parts
        for idx, module_part in enumerate(module_import_path.parts):
            if "site-packages" in module_part:
                module_root = module_import_path.parts[idx + 1]
                break

        module_source_path = Path(module_import_path.as_posix().split(module_root)[0]) / module_root
        module_destination_path = HOPPER_SCRIPTS_PATH / module_root
    else:
        module_source_path = module_import_path.parent
        module_destination_path = HOPPER_SCRIPTS_PATH / module_source_path.name
    print(f"{module_source_path} -> {module_destination_path}")

    try:
        if module_source_path.is_dir():
            shutil.copytree(module_source_path, module_destination_path)
        else:
            shutil.copy(module_source_path, module_destination_path)
    except Exception as e:
        print(f"failed to copy {module_source_path} to {module_destination_path}: {e}")
