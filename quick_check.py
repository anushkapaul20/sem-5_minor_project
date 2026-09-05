from engine.protocols.nspk import make_nspk, make_nsl
from engine.protocols.nssk import make_nssk
from engine.protocols.iso9798 import make_iso9798
from engine.protocols.sts import make_sts
from engine.protocols.mqv import make_mqv
from engine.explorer import Explorer

cases = [
    (make_nspk,    True,  "NSPK"),
    (make_nsl,     False, "NSL"),
    (make_nssk,    True,  "NSSK"),
    (make_iso9798, True,  "ISO9798"),
    (make_sts,     True,  "STS"),
    (make_mqv,     True,  "MQV"),
]

e = Explorer(max_sessions=2, depth_limit=15, timeout_seconds=20)
correct = 0
for fn, expected, name in cases:
    r = e.verify(fn())
    ok = r.attack_found == expected
    correct += int(ok)
    tick = "OK  " if ok else "FAIL"
    print(f"[{tick}] {name:<10} expected={'ATTACK' if expected else 'SECURE'} got={'ATTACK' if r.attack_found else 'SECURE'} type={r.attack_type} states={r.states_visited} time={r.time_seconds:.1f}s")

print(f"\nAccuracy: {correct}/{len(cases)} = {correct/len(cases):.0%}")
