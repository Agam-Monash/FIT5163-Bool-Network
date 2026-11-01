"""python main.py  -- run several full epochs: sortition -> DKG/handover -> signing."""
import time

from src.curve import enc
from src.epoch import Network, sign
from src.threshold_signing import verify

net = Network(num_nodes=12)
gpk0 = None
for _ in range(3):
    t0 = time.time()
    c = net.advance()
    kind = "DKG" if c.epoch == 0 else "handover"
    gpk0 = gpk0 or c.gpk
    msg = f"epoch {c.epoch}: release 1 BTC".encode()
    sig = sign(c, msg)
    print(f"epoch {c.epoch}: committee n={c.size} t={c.threshold}  [{kind}]  "
          f"gpk unchanged={c.gpk == gpk0}  sig valid={verify(msg, sig, enc(c.gpk))}  "
          f"({time.time() - t0:.1f}s)")
