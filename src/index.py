import os
import platform

import uvicorn

os.environ["LITESTAR_WARN_IMPLICIT_SYNC_TO_THREAD"] = "0"

from checkmail.server import app

loop = "auto"
if platform.system == "Windows":
    uvicorn.config.LOOP_SETUPS["winloop"] = "checkmail.loops.winloop:winloop_setup"
    loop = "winloop"

uvicorn.run(app, host="0.0.0.0", loop=loop)
