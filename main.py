from ecdsa import curves, ellipticcurve
import secrets


class ECPoint:
    def __init__(self, x, y):
        self.x = x
        self.y = y

def ec_point_gen(x, y):
    point = ECPoint(x, y)
    if is_on_curve_check(point):
        return point
    return False


def base_point_g_get():
    _curve = curves.NIST256p
    _base_point = _curve.generator
    _base_point = ECPoint(_base_point.x(), _base_point.y())
    return _base_point

def get_base_curve():
    _curve = curves.NIST256p.curve
    return _curve

def is_on_curve_check( _point: ECPoint):
    try:
        _curve  = get_base_curve()
        _f = ellipticcurve.Point(_curve, _point.x, _point.y)
    except AssertionError:
        return False
    return True

def add_ec_points(_a: ECPoint, _b: ECPoint):
    _curve = get_base_curve()
    _a = ellipticcurve.Point(_curve, _a.x, _a.y)
    _b = ellipticcurve.Point(_curve, _b.x, _b.y)
    _c = _a + _b
    _c = ECPoint(_c.x(), _c.y())
    return _c

def double_ec_points(point: ECPoint):
    _curve = get_base_curve()
    point = ellipticcurve.Point(_curve, point.x, point.y)
    point.double()
    point = ECPoint(point.x(), point.y())
    return point

def scalar_multiple(k, point: ECPoint):
    _curve = get_base_curve()
    point = ellipticcurve.Point(_curve, point.x, point.y)
    point_2 = k * point
    point_2 = ECPoint(point_2.x(),point_2.y())
    return point_2

def is_equal_points(point_1: ECPoint, point_2: ECPoint):
    return (point_1.x == point_2.x) and (point_1.y == point_2.y)

def ec_point_to_string(point: ECPoint):
    string = str(point.x) + " " + str(point.y)
    return string

def string_to_ec_point(string:str):
    res = string.split()
    point = ECPoint(int(res[0]), int(res[1]))
    return point

def print_ec_point(point: ECPoint):
    print(f"x: {point.x}, y: {point.y}")

def private_key_gen():
    curve = curves.NIST256p
    key = secrets.randbelow(curve.order)
    return key

def public_key_gen(private_key):
    g = base_point_g_get()
    key = scalar_multiple(private_key, g)
    return key

def shared_key_gen(private_key, foreign_public_key):
    key = scalar_multiple(private_key, foreign_public_key)
    return key.x

if __name__ == '__main__':
    private_key_1 = private_key_gen()
    public_key_1 = public_key_gen(private_key_1)
    print(f"private key 1: {private_key_1}")
    print("public key 1:")
    print_ec_point(public_key_1)
    print()

    private_key_2 = private_key_gen()
    public_key_2  = public_key_gen(private_key_2)
    print(f"private key 2: {private_key_2}")
    print("public key 2:")
    print_ec_point(public_key_2)
    print()

    shared_key_1 = shared_key_gen(private_key_1, public_key_2)
    shared_key_2 = shared_key_gen(private_key_2, public_key_1)
    print(f"shared key 1: {shared_key_1}")
    print(f"shared key 2: {shared_key_2}")

    print(f"shared key 1 = shared key 2: {shared_key_1==shared_key_2}")
