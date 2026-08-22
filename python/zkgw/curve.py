"""secp256k1 group operations (pure Python, Jacobian coordinates).

Educational/reference implementation for the ZK Proof Gateway prototype.
NOT constant-time; do not use with long-term secrets in production.
"""
from __future__ import annotations
import hashlib
from dataclasses import dataclass

# secp256k1 parameters
P = 2**256 - 2**32 - 977
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
Gx = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
Gy = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8
B = 7


@dataclass(frozen=True)
class Point:
    """Affine point; None-coords sentinel = identity."""
    x: int | None
    y: int | None

    def is_identity(self) -> bool:
        return self.x is None

    def compress(self) -> bytes:
        if self.is_identity():
            return b"\x00" * 33
        return bytes([2 + (self.y & 1)]) + self.x.to_bytes(32, "big")

    def __add__(self, other: "Point") -> "Point":
        return _to_affine(_jadd(_to_jac(self), _to_jac(other)))

    def __neg__(self) -> "Point":
        if self.is_identity():
            return self
        return Point(self.x, (-self.y) % P)

    def __sub__(self, other: "Point") -> "Point":
        return self + (-other)

    def __rmul__(self, k: int) -> "Point":
        return _to_affine(_jmul(_to_jac(self), k % N))


IDENTITY = Point(None, None)
G = Point(Gx, Gy)

# ---- Jacobian internals: (X, Y, Z), affine x = X/Z^2, y = Y/Z^3 ----
_JID = (0, 1, 0)


def _to_jac(pt: Point):
    if pt.is_identity():
        return _JID
    return (pt.x, pt.y, 1)


def _to_affine(J) -> Point:
    X, Y, Z = J
    if Z == 0:
        return IDENTITY
    zi = pow(Z, -1, P)
    zi2 = zi * zi % P
    return Point(X * zi2 % P, Y * zi2 * zi % P)


def _jdouble(J):
    X, Y, Z = J
    if Z == 0 or Y == 0:
        return _JID
    S = 4 * X * Y * Y % P
    M = 3 * X * X % P  # a=0 for secp256k1
    X2 = (M * M - 2 * S) % P
    Y2 = (M * (S - X2) - 8 * pow(Y, 4, P)) % P
    Z2 = 2 * Y * Z % P
    return (X2, Y2, Z2)


def _jadd(J1, J2):
    if J1[2] == 0:
        return J2
    if J2[2] == 0:
        return J1
    X1, Y1, Z1 = J1
    X2, Y2, Z2 = J2
    Z1Z1 = Z1 * Z1 % P
    Z2Z2 = Z2 * Z2 % P
    U1 = X1 * Z2Z2 % P
    U2 = X2 * Z1Z1 % P
    S1 = Y1 * Z2 * Z2Z2 % P
    S2 = Y2 * Z1 * Z1Z1 % P
    if U1 == U2:
        if S1 != S2:
            return _JID
        return _jdouble(J1)
    H = (U2 - U1) % P
    R = (S2 - S1) % P
    H2 = H * H % P
    H3 = H * H2 % P
    U1H2 = U1 * H2 % P
    X3 = (R * R - H3 - 2 * U1H2) % P
    Y3 = (R * (U1H2 - X3) - S1 * H3) % P
    Z3 = H * Z1 * Z2 % P
    return (X3, Y3, Z3)


def _jmul(J, k: int):
    acc = _JID
    add = J
    while k:
        if k & 1:
            acc = _jadd(acc, add)
        add = _jdouble(add)
        k >>= 1
    return acc


def multi_scalar_weighted(points: list[Point], weights: list[int]) -> Point:
    """Sum_i weights[i] * points[i] (simple loop; fine for prototype)."""
    acc = _JID
    for pt, w in zip(points, weights):
        acc = _jadd(acc, _jmul(_to_jac(pt), w % N))
    return _to_affine(acc)


def hash_to_curve(label: bytes) -> Point:
    """Deterministic nothing-up-my-sleeve generator via try-and-increment."""
    ctr = 0
    while True:
        h = hashlib.sha256(b"zkgw/h2c/v1|" + label + b"|" + ctr.to_bytes(4, "big")).digest()
        x = int.from_bytes(h, "big") % P
        y2 = (pow(x, 3, P) + B) % P
        y = pow(y2, (P + 1) // 4, P)
        if y * y % P == y2:
            return Point(x, y if y % 2 == 0 else P - y)
        ctr += 1


# Second Pedersen generator H with unknown discrete log w.r.t. G.
H = hash_to_curve(b"pedersen-H")
