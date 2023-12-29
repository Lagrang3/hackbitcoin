from .context import hackbitcoin

import pytest
from hackbitcoin.secp256k1 import FieldElement, is_prime, Point, secp256k1_Point


def test_prime():
    for i in [0,1,4,6,8,9,10,12,14,15,16,18,20]:
        assert is_prime(i)==False

    for i in [2,3,5,7,11,13,17,19]:
        assert is_prime(i)==True


def test_FieldElement_eq():
    a = FieldElement(3,13)
    b = FieldElement(3,13)
    c = FieldElement(0,13)
    d = FieldElement(0,13)
    assert (a==b and b==a)
    assert (c==d and d==c)
    assert (a!=c and c!=a)
    assert (a!=d and d!=a)
    assert (b!=c and c!=b)
    assert (b!=d and d!=b)
    assert (a!=0 and 0!=a)
    assert (b!=0 and 0!=b)
    assert (c==0 and 0==c)
    assert (d==0 and 0==d)
    for i in range(1,20):
        assert (a!=i and i!=a)
        assert (b!=i and i!=b)
        assert (c!=i and i!=c)
        assert (d!=i and i!=d)


def test_FieldElement_add():
    a = FieldElement(3,13)
    b = FieldElement(5,13)
    c = FieldElement(10,13)
    # no shallow copy
    d = a+b
    d.num=0
    assert(a.num==3)
    assert(b.num==5)
    # correct sum under the prime
    assert((a+b)==FieldElement(8,13))
    assert((a+c)==0)
    assert((b+c)==FieldElement(2,13))


def test_Point_ctor():
    with pytest.raises(ValueError):
        Point(2,4,5,7)
    with pytest.raises(ValueError):
        Point(5,7,5,7)
    # ok
    Point(-1,-1,5,7)
    Point(18,77,5,7)
    a = Point(None,None,5,7)
    assert(a==0)


def test_Point_add():
    p1 = Point(-1,-1,5,7)
    p2 = Point(-1,1,5,7)
    inf = Point(None,None,5,7)
    assert inf == (p1+p2)

    p1 = Point(2,0,0,-8)
    assert 0==(p1+p1)


def test_Point_discrete():
    prime=223
    a = FieldElement(0,prime)
    b = FieldElement(7,prime)
    valid_points = [(192,105), (17,56), (1,193)]
    invalid_points = [(200,119), (42,99)]
    for x_raw,y_raw in valid_points:
        x = FieldElement(x_raw,prime)
        y = FieldElement(y_raw,prime)
        Point(x,y,a,b)
    for x_raw,y_raw in invalid_points:
        x = FieldElement(x_raw,prime)
        y = FieldElement(y_raw,prime)
        with pytest.raises(ValueError):
            Point(x,y,a,b)


def test_Point_discrete_add():
    prime = 223
    a = FieldElement(0,prime)
    b = FieldElement(7,prime)
    x1 = FieldElement(192,prime)
    y1 = FieldElement(105,prime)
    x2 = FieldElement(17,prime)
    y2 = FieldElement(56,prime)
    p1 = Point(x1,y1,a,b)
    p2 = Point(x2,y2,a,b)

    rx = FieldElement(170,prime)
    ry = FieldElement(142,prime)
    assert (p1+p2) == Point(rx,ry,a,b)


def test_Point_scalar_multiplication():
    prime = 223
    a = FieldElement(0,prime)
    b = FieldElement(7,prime)
    x = FieldElement(47,prime)
    y = FieldElement(71,prime)
    p = Point(x,y,a,b)
    for s in range(1,21):
        sp = s*p
        ssp = Point(None,None,a,b)
        for i in range(s):
            ssp += p
        assert sp==ssp


def test_secp256k1_generator():
    N = secp256k1_Point.N
    G = secp256k1_Point.generator()
    G_lift = secp256k1_Point.lift(secp256k1_Point.Gx,even=True)
    assert G==G_lift
    assert secp256k1_Point(None,None)==0
    assert N*G==0
    assert (N+1)*G==G
