# Mathematical foundations of Elliptic Curve Cryptography.
# and in particular the use of SECP256k1 curve

def is_prime(x: int):
    """Test wether x is a prime number"""
    # FIXME: do a prime test here that is not too expensive
    pset = {2,3,5,7,11,13,17,19}
    if x<2:
        return False
    if x in pset:
        return True
    for p in pset:
        if x%p==0:
            return False
    # x is probably prime
    return True


class FieldElement:
    """
    Represents the a algebraic field of modular integers by a prime number.
    """
    def __init__(self,num: int,prime: int,check_prime: bool=True):
        if check_prime:
            # be sure that we are dealing with a prime number here,
            # sometimes this is not necessary and we skip this computation
            if not is_prime(prime):
                error = 'Number {} is not prime'.format(prime)
                raise ValueError(error)
        if num>= prime or num<0:
            error = 'Num {} not in field range 0 to {}'.format(num,prime-1)
            raise ValueError(error)
        self.num=num
        self.prime=prime


    def __repr__(self):
        """Ah!, a printable expression."""
        return 'FieldElement_{}({})'.format(self.prime,self.num)


    def __eq__(self,other):
        if other is None:
            return False
        # allow to compare to 0
        if isinstance(other,int):
            return self.num==other and other==0
        return self.num==other.num and self.prime==other.prime


    def __add__(self,other):
        if self.prime != other.prime:
            raise TypeError('Cannot add two numbers in different Fields')
        # This should be faster than using the remainder operator
        num = self.num + other.num
        if num>= self.prime:
            num -= self.prime
        return self.__class__(num,self.prime,check_prime=False)


    def __mul__(self,other):
        if self.prime != other.prime:
            raise TypeError('Cannot multiply two numbers in different Fields')
        num = (self.num * other.num)%self.prime
        return self.__class__(num,self.prime,check_prime=False)


    def __rmul__(self,scalar: int):
        """Scalar multiplication on the Left"""
        s = scalar % self.prime
        num = (s*self.num) % self.prime
        return self.__class__(num,self.prime,check_prime=False)


    def inverse(self):
        """Produces the multiplicative inverse."""
        # Using Fermat's little theorem here
        num = pow(self.num,self.prime-2,self.prime)
        return self.__class__(num,self.prime,check_prime=False)


    def __neg__(self):
        num = self.prime - self.num
        # This should be faster than using the remainder operator
        if num==self.prime:
            num=0
        return self.__class__(num,self.prime,check_prime=False)


    def __sub__(self,other):
        return self + (-other)


    def __truediv__(self,other):
        return self*other.inverse()


    def __hash__(self):
        return hash((self.num,self.prime))


    def __pow__(self,exponent: int):
        # using Fermat's little theorem here
        num = pow(self.num,exponent % (self.prime-1),self.prime)
        return self.__class__(num,self.prime,check_prime=False)



class Point:
    """A point in an elliptic curve."""
    def __init__(self,x,y,a,b,check=True):
        self.a=a
        self.b=b
        self.x=x
        self.y=y
        if self.x==None and self.y==None:
            return
        if check:
            # Check only if it is required
            if self.y**2 != self.x**3 + a*x + b:
                raise ValueError('({},{}) is not on the curve'.format(x,y))


    def __repr__(self):
        """Ah!, a printable expression."""
        return 'Point({},{}) on Curve({},{})'.format(self.x,self.y,self.a,self.b)


    def __eq__(self,other):
        """Equality. A curve's null element can be compared to int(0)."""
        if isinstance(other,int):
            return other==0 and self.x is None and self.y is None
        return self.x==other.x and self.y==other.y and \
            self.a==other.a and self.b==other.b


    def inverse(self):
        return self.__class__(self.x,-self.y,self.a,self.b,check=False)


    def __add__(self,other):
        """Curve points addition."""
        if self.a!=other.a or self.b!=other.b:
            raise TypeError('Points {}, {} are not on the same curve'.format(
                self,other))
        # Case neutral element:
        if self.x is None:
            return self.__class__(other.x,other.y,other.a,other.b,check=False)
        if other.x is None:
            return self.__class__(self.x,self.y,self.a,self.b,check=False)
        if self.x!=other.x:
            # line's slope
            m = (other.y - self.y)/(other.x-self.x)
            # compute the point's x
            x3 = m*m - self.x - other.x
            # the point's y is in the line, but negative
            y3 = m*(x3-self.x) + self.y
            return self.__class__(x3,-y3,self.a,self.b,check=False)
        # now x1==x2
        if self.y==other.y and self.y!=0 and self.x==other.x:
            # line's slope
            m = (3*self.x*self.x + self.a)/(2*self.y)
            # compute the point's x
            x3 = m*m - self.x - self.x
            # the point's y is in the line, but negative
            y3 = m*(x3 - self.x) + self.y
            return self.__class__(x3,-y3,self.a,self.b,check=False)
        if (self.y+other.y)==0 and self.x==other.x:
            # using (x,y)+(x,-y), this gives the neutral element
            return self.__class__(None,None,self.a,self.b,check=False)
        raise RuntimeError(
            "Something's wrong, we should have handled all cases.")


    def __sub__(self,other):
        return self + other.inverse()


    def __rmul__(self,scalar: int):
        """Scalar multiplication on the Left"""
        current = self.__class__(self.x,self.y,self.a,self.b)
        result = self.__class__(None,None,self.a,self.b)
        while scalar:
            if scalar & 1:
                result += current
            current += current
            scalar >>= 1
        return result


class secp256k1_Field(FieldElement):
    P = 2**256 - 2**32 - 977 # secp256k1's prime

    def __init__(self,num,prime=None,check_prime=None):
        super().__init__(num=num,prime=secp256k1_Field.P,check_prime=False)


    def __repr__(self):
        """Hexadecimal representation"""
        return '{:x}'.format(self.num).zfill(64)


    def sqrt(self):
        """Square root.
        notice
        x^{P-1}=1 (due to Fermat's theorem)
        then x^{P+1}=x^2
        hence x^{(P+1)/2}=x,
        on the other hand P+1 mod 4 = 0 so we can define
        y=x^{(P+1)/4}
        but y*y = x^{(P+1)/2} = x
        therefore y=sqrt(x)."""
        return self**((secp256k1_Field.P+1)//4)



class secp256k1_Point(Point):
    # curve parameters
    a = secp256k1_Field(0)
    b = secp256k1_Field(7)

    # group order
    N =  0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141

    # group generator
    Gx = secp256k1_Field(0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798)
    Gy = secp256k1_Field(0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8)

    @classmethod
    def identity(cls):
        return cls(None,None)

    @classmethod
    def lift(cls,x,even=True):
        """Obtains a point from a know value of the x coordinate. The bool even
        selects one of the two possible solutions for y."""
        assert type(cls.a)==type(cls.b) and type(cls.a)==type(x)
        y2 = x**3 + cls.a*x + cls.b
        y = y2.sqrt()
        if not (even ==  bool(y.num % 2 == 0)):
            y = -y
        return cls(x,y)

    @classmethod
    def generator(cls):
        return cls(cls.Gx,cls.Gy)

    def __init__(self,x,y,a=None,b=None,check=None):
        if isinstance(x,int) and isinstance(y,int):
            super().__init__(x=secp256k1_Field(x),
                             y=secp256k1_Field(y),
                             a=secp256k1_Point.a,
                             b=secp256k1_Point.b)
        else:
            super().__init__(x,y,secp256k1_Point.a,secp256k1_Point.b)


    def __rmul__(self,scalar: int):
        # use group order
        return super().__rmul__(scalar % self.N)


    def __repr__(self):
        if self==0:
            return 'secp256k1_Point(NULL)'
        return 'secp256k1_Point({},{})'.format(self.x,self.y)



