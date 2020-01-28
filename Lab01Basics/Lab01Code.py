#####################################################
# GA17 Privacy Enhancing Technologies -- Lab 01
#
# Basics of Petlib, encryption, signatures and
# an end-to-end encryption system.
#
# Run the tests through:
# $ py.test-2.7 -v Lab01Tests.py 

###########################
# Group Members: TODO
###########################


#####################################################
# TASK 1 -- Ensure petlib is installed on the System
#           and also pytest. Ensure the Lab Code can 
#           be imported.

import petlib

#####################################################
# TASK 2 -- Symmetric encryption using AES-GCM 
#           (Galois Counter Mode)
#
# Implement a encryption and decryption function
# that simply performs AES_GCM symmetric encryption
# and decryption using the functions in petlib.cipher.

from os import urandom
from petlib.cipher import Cipher


def encrypt_message(K, message):
    """ Encrypt a message under a key K """

    plaintext = message.encode("utf8")

    ## YOUR CODE HERE

    iv = urandom(16)  # get random 16byte IV
    aes = Cipher.aes_128_gcm()  # Initialize AES-GCM with 128 bit keys

    ciphertext, tag = aes.quick_gcm_enc(K, iv, plaintext)  # perform encryption

    return (iv, ciphertext, tag)


def decrypt_message(K, iv, ciphertext, tag):
    """ Decrypt a cipher text under a key K 

        In case the decryption fails, throw an exception.
    """
    ## YOUR CODE HERE
    aes = Cipher.aes_128_gcm()  # Initialize AES-GCM with 128 bit keys
    plain = aes.quick_gcm_dec(K, iv, ciphertext, tag)  # perform decryption

    return plain.encode("utf8")


#####################################################
# TASK 3 -- Understand Elliptic Curve Arithmetic
#           - Test if a point is on a curve.
#           - Implement Point addition.
#           - Implement Point doubling.
#           - Implement Scalar multiplication (double & add).
#           - Implement Scalar multiplication (Montgomery ladder).
#
# MUST NOT USE ANY OF THE petlib.ec FUNCIONS. Only petlib.bn!

from petlib.bn import Bn


def is_point_on_curve(a, b, p, x, y):
    """
    Check that a point (x, y) is on the curve defined by a,b and prime p.
    Reminder: an Elliptic Curve on a prime field p is defined as:

              y^2 = x^3 + ax + b (mod p)
                  (Weierstrass form)

    Return True if point (x,y) is on curve, otherwise False.
    By convention a (None, None) point represents "infinity".
    """
    assert isinstance(a, Bn)
    assert isinstance(b, Bn)
    assert isinstance(p, Bn) and p > 0
    assert (isinstance(x, Bn) and isinstance(y, Bn)) \
           or (x is None and y is None)

    if x is None and y is None:
        return True

    lhs = (y * y) % p
    rhs = (x * x * x + a * x + b) % p
    on_curve = (lhs == rhs)

    return on_curve


def point_add(a, b, p, x0, y0, x1, y1):
    """Define the "addition" operation for 2 EC Points.

    Reminder: (xr, yr) = (xq, yq) + (xp, yp)
    is defined as:
        lam = (yq - yp) * (xq - xp)^-1 (mod p)
        xr  = lam^2 - xp - xq (mod p)
        yr  = lam * (xp - xr) - yp (mod p)

    Return the point resulting from the addition. Raises an Exception if the points are equal.
    """

    # ADD YOUR CODE BELOW

    # Check if points are on the curve
    if is_point_on_curve(a, b, p, x0, y0) and is_point_on_curve(a, b, p, x1, y1):
        # Check if one point is infinity (identity). Return the appropriate value
        if (x1 is None) and (y1 is None):
            if (x0 is None) and (y0 is None):
                return None, None
            else:
                return x0, y0
        elif (x0 is None) and (y0 is None):
            if (x1 is None) and (y1 is None):
                return None, None
            else:
                return x1, y1

        # Check that points are different
        if (y1 == y0) and (x1 == x0):
            raise Exception("EC Points must not be equal")
        elif (y1 == y0.mod_mul(-1, p)) and (x1 == x0):
            return None, None

        slope = ((y1 - y0) * (x1 - x0).mod_inverse(p)) % p

        xr = (slope ** 2 - x0 - x1) % p
        yr = (slope * (x0 - xr) - y0) % p
        # xr, yr = None, None

        return (xr, yr)
    else:
        raise Exception("At least one of the points is not on the curve")


def point_double(a, b, p, x, y):
    """Define "doubling" an EC point.
     A special case, when a point needs to be added to itself.

     Reminder:
        lam = (3 * xp ^ 2 + a) * (2 * yp) ^ -1 (mod p)
        xr  = lam ^ 2 - 2 * xp (mod p)
        yr  = lam * (xp - xr) - yp (mod p)

    Returns the point representing the double of the input (x, y).
    """

    # ADD YOUR CODE BELOW
    if is_point_on_curve(a, b, p, x, y):
        if (x is None) and (y is None):
            return None, None
        slope = ((3 * x ** 2 + a) * (2 * y).mod_inverse(p)) % p
        xr = (slope ** 2 - 2 * x) % p
        yr = (slope * (x - xr) - y) % p

        return xr, yr
    else:
        raise Exception("Point not on curve")


def point_scalar_multiplication_double_and_add(a, b, p, x, y, scalar):
    """
    Implement Point multiplication with a scalar:
        r * (x, y) = (x, y) + ... + (x, y)    (r times)

    Reminder of Double and Multiply algorithm: r * P
        Q = infinity
        for i = 0 to num_bits(P)-1
            if bit i of r == 1 then
                Q = Q + P
            P = 2 * P
        return Q

    """
    # Check that the point is on the curve.
    # If so apply the algorithm, otherwise raise an exception
    if is_point_on_curve(a, b, p, x, y):
        Q = (None, None)
        P = (x, y)

        for i in range(scalar.num_bits()):
            if scalar.is_bit_set(i):  # Check if the i-th bit is set and perform addition
                Q = point_add(a, b, p, Q[0], Q[1], P[0], P[1])
            P = point_double(a, b, p, P[0], P[1])

        return Q
    else:
        raise Exception("Point not on curve")



def point_scalar_multiplication_montgomerry_ladder(a, b, p, x, y, scalar):
    """
    Implement Point multiplication with a scalar:
        r * (x, y) = (x, y) + ... + (x, y)    (r times)

    Reminder of Double and Multiply algorithm: r * P
        R0 = infinity
        R1 = P
        for i in num_bits(P)-1 to zero:
            if di = 0:
                R1 = R0 + R1
                R0 = 2R0
            else
                R0 = R0 + R1
                R1 = 2 R1
        return R0

    """
    # Check that the point is on the curve.
    # If so apply the algorithm, otherwise raise an exception
    if is_point_on_curve(a, b, p, x, y):
        R0 = (None, None)
        R1 = (x, y)

        for i in reversed(range(0, scalar.num_bits())):
            if not scalar.is_bit_set(i):
                R1 = point_add(a, b, p, R0[0], R0[1], R1[0], R1[1])
                R0 = point_double(a, b, p, R0[0], R0[1])
            else:
                R0 = point_add(a, b, p, R0[0], R0[1], R1[0], R1[1])
                R1 = point_double(a, b, p, R1[0], R1[1])
        return R0
    else:
        raise Exception("Point not on curve")





#####################################################
# TASK 4 -- Standard ECDSA signatures
#
#          - Implement a key / param generation 
#          - Implement ECDSA signature using petlib.ecdsa
#          - Implement ECDSA signature verification 
#            using petlib.ecdsa

from hashlib import sha256
from petlib.ec import EcGroup
from petlib.ecdsa import do_ecdsa_sign, do_ecdsa_verify


def ecdsa_key_gen():
    """ Returns an EC group, a random private key for signing 
        and the corresponding public key for verification"""
    G = EcGroup()
    priv_sign = G.order().random()
    pub_verify = priv_sign * G.generator()
    return (G, priv_sign, pub_verify)


def ecdsa_sign(G, priv_sign, message):
    """ Sign the SHA256 digest of the message using ECDSA and return a signature """
    plaintext = message.encode("utf8")

    ## YOUR CODE HERE
    digest = sha256(plaintext).digest()  # securely hash the message using the built-in library
    sig = do_ecdsa_sign(G, priv_sign, digest)  # sign using the private key and the function provided in petlib
    return sig


def ecdsa_verify(G, pub_verify, message, sig):
    """ Verify the ECDSA signature on the message """
    plaintext = message.encode("utf8")

    ## YOUR CODE HERE
    digest = sha256(plaintext).digest()  # securely hash the message using the built-in library
    res = do_ecdsa_verify(G, pub_verify, sig, digest)  # verify using the public key and the function provided in petlib
    return res


#####################################################
# TASK 5 -- Diffie-Hellman Key Exchange and Derivation
#           - use Bob's public key to derive a shared key.
#           - Use Bob's public key to encrypt a message.
#           - Use Bob's private key to decrypt the message.
#
# NOTE: 

def dh_get_key():
    """ Generate a DH key pair """
    G = EcGroup()
    priv_dec = G.order().random()
    pub_enc = priv_dec * G.generator()
    return (G, priv_dec, pub_enc)


def dh_encrypt(pub, message, aliceSig=None):
    """ Assume you know the public key of someone else (Bob), 
    and wish to Encrypt a message for them.
        - Generate a fresh DH key for this message.
        - Derive a fresh shared key.
        - Use the shared key to AES_GCM encrypt the message.
        - Optionally: sign the message with Alice's key.
    """

    ## YOUR CODE HERE
    G, alice_priv, alice_pub = dh_get_key()  # derive fresh keys

    shared_secret = alice_priv * pub  # derive the shared secret

    session_key = sha256(shared_secret.export()).digest()  # use shared secret to derive a unique 256-bit session key

    plaintext = message.encode("utf8")  # prepare the plaintext for encryption
    iv = urandom(32)  # generate a 256-bit random value
    aes = Cipher.aes_256_gcm()  # Initialize AES-GCM with 256 bit keys
    ciphertext, tag = aes.quick_gcm_enc(session_key, iv, plaintext)  # perform encryption using AES

    # check whether to implement the signature
    if aliceSig is None:
        bundle = (alice_pub, iv, ciphertext, tag)
    else:
        sig = ecdsa_sign(G, aliceSig, message)
        bundle = (alice_pub, iv, ciphertext, tag, sig)
    return bundle


def dh_decrypt(priv, bundle, aliceVer=None):
    """ Decrypt a received message encrypted using your public key, 
    of which the private key is provided. Optionally verify 
    the message came from Alice using her verification key."""

    ## YOUR CODE HERE

    # Check whether signature was implemented. Unpack the bundle accordingly
    if aliceVer is None:
        if len(bundle) != 4:
            raise Exception("decryption failed: missing input arguments")
        else:
            alice_pub, iv, ciphertext, tag = bundle
    else:
        if len(bundle) != 5:
            raise Exception("decryption failed: missing input arguments")
        else:
            alice_pub, iv, ciphertext, tag, sig = bundle

    shared_secret = priv * alice_pub  # derive the shared secret
    session_key = sha256(shared_secret.export()).digest()  # use shared secret to derive a unique 256-bit session key
    aes = Cipher.aes_256_gcm()  # Initialize AES-GCM with 256 bit keys
    plain = aes.quick_gcm_dec(session_key, iv, ciphertext, tag)  # perform decryption using AES

    message = plain.encode("utf8")

    if (aliceVer is not None):
        sign_check = ecdsa_verify(EcGroup(), aliceVer, message, sig)
        if not sign_check:
            raise Exception("decryption failed: signature does not verify")

    return message


## NOTE: populate those (or more) tests
#  ensure they run using the "py.test filename" command.
#  What is your test coverage? Where is it missing cases?
#  $ py.test-2.7 --cov-report html --cov Lab01Code Lab01Code.py 

def test_encrypt():
    G, bob_priv, bob_pub = dh_get_key()
    message = u"Hello World!"
    bundled_ciphertext = dh_encrypt(bob_pub, message, aliceSig=None)
    alice_pub, iv, ciphertext, tag = bundled_ciphertext

    assert len(iv) == 32
    assert len(ciphertext) == len(message)
    assert len(tag) == 16


def test_encrypt_with_sig():
    G, bob_priv, bob_pub = dh_get_key()
    message = u"Hello World!"

    G, aliceSig, aliceVer = ecdsa_key_gen()

    bundled_ciphertext = dh_encrypt(bob_pub, message, aliceSig)
    alice_pub, iv, ciphertext, tag, sig = bundled_ciphertext

    assert ecdsa_verify(G, aliceVer, message, sig)


def test_decrypt():
    G, bob_priv, bob_pub = dh_get_key()
    message = u"Hello World!"
    bundled_ciphertext = dh_encrypt(bob_pub, message, aliceSig=None)
    alice_pub, iv, ciphertext, tag = bundled_ciphertext

    assert len(iv) == 32
    assert len(ciphertext) == len(message)
    assert len(tag) == 16

    m = dh_decrypt(bob_priv, bundled_ciphertext)
    assert m == message


def test_decrypt_with_sig():
    G, bob_priv, bob_pub = dh_get_key()
    message = u"Hello World!"

    G, aliceSig, aliceVer = ecdsa_key_gen()

    bundled_ciphertext = dh_encrypt(bob_pub, message, aliceSig)
    alice_pub, iv, ciphertext, tag, sig = bundled_ciphertext

    assert len(iv) == 32
    assert len(ciphertext) == len(message)
    assert len(tag) == 16

    m = dh_decrypt(bob_priv, bundled_ciphertext, aliceVer)
    assert m == message


def test_fails():
    from pytest import raises

    G, bob_priv, bob_pub = dh_get_key()
    message = u"Hello World!"
    bundled_ciphertext = dh_encrypt(bob_pub, message, aliceSig=None)
    alice_pub, iv, ciphertext, tag = bundled_ciphertext
    G, test_priv, test_pub = dh_get_key()

    with raises(Exception) as excinfo:
        dh_decrypt(bob_priv, (iv, ciphertext, tag))
    assert 'decryption failed' in str(excinfo.value)

    with raises(Exception) as excinfo:
        dh_decrypt(bob_priv, (alice_pub, iv, ciphertext))
    assert 'decryption failed' in str(excinfo.value)

    with raises(Exception) as excinfo:
        dh_decrypt(bob_priv, (alice_pub, tag))
    assert 'decryption failed' in str(excinfo.value)

    with raises(Exception) as excinfo:
        dh_decrypt(bob_priv, (alice_pub, iv, ciphertext * 2, tag))
    assert 'decryption failed' in str(excinfo.value)

    with raises(Exception) as excinfo:
        dh_decrypt(bob_priv, (test_pub, iv, ciphertext, tag))
    assert 'decryption failed' in str(excinfo.value)

    with raises(Exception) as excinfo:
        dh_decrypt(bob_priv, (alice_pub, iv, urandom(len(message)), tag))
    assert 'decryption failed' in str(excinfo.value)

    with raises(Exception) as excinfo:
        dh_decrypt(bob_priv, (alice_pub, iv, ciphertext, urandom(16)))
    assert 'decryption failed' in str(excinfo.value)

    with raises(Exception) as excinfo:
        dh_decrypt(bob_priv, (alice_pub, urandom(32), ciphertext, tag))
    assert 'decryption failed' in str(excinfo.value)

    G, aliceSig, aliceVer = ecdsa_key_gen()

    bundled_ciphertext = dh_encrypt(bob_pub, message, aliceSig)
    alice_pub, iv, ciphertext, tag, sig = bundled_ciphertext
    sig2 = ecdsa_sign(G, aliceSig, "some other message")

    with raises(Exception) as excinfo:
        dh_decrypt(bob_priv, (alice_pub, iv, ciphertext, tag, sig2), aliceVer)
    assert 'decryption failed' in str(excinfo.value)

    G, attackerSig, attackerVer = ecdsa_key_gen()
    sig3 = ecdsa_sign(G, attackerSig, "some other message")

    with raises(Exception) as excinfo:
        dh_decrypt(bob_priv, (alice_pub, iv, ciphertext, tag, sig3), aliceVer)
    assert 'decryption failed' in str(excinfo.value)


#####################################################
# TASK 6 -- Time EC scalar multiplication
#             Open Task.
#           
#           - Time your implementations of scalar multiplication
#             (use time.clock() for measurements)for different 
#              scalar sizes)
#           - Print reports on timing dependencies on secrets.
#           - Fix one implementation to not leak information.

def time_scalar_mul(N=100):
    # Calculate the correlation between the number of bits set in the scalar and the time it takes to run multiplication
    # using the double-and-add algorithm. While we expect to find a strong linear relationship (for each set bit, there
    # should be one extra point addition), this is not what is observed: correlation between number of set bits and
    # time elapsed is usually between 0 and 0.4; except on the first run of the code where it is usually approx 0.6
    #
    # NOTE: for this function to run, you will need to install the scipy package
    #

    import time
    from scipy.stats import pearsonr

    G = EcGroup(713)  # NIST curve
    d = G.parameters()
    a, b, p = d["a"], d["b"], d["p"]
    g = G.generator()
    gx0, gy0 = g.get_affine()

    set_bits = []
    time_elapsed = []
    scalar = []
    for i in range(0,N):
        r = G.order().random()
        scalar.append(r)
        bit_counter = 0
        for i in range(r.num_bits()):
            if r.is_bit_set(i):  # Check if the i-th bit is set and perform addition
                bit_counter = bit_counter + 1
        set_bits.append(bit_counter)

        t0 = time.clock()
        x2, y2 = point_scalar_multiplication_double_and_add(a, b, p, gx0, gy0, r)
        t1 = time.clock()
        time_elapsed.append(t1-t0)

    corr, _ = pearsonr(set_bits, time_elapsed)

    print 'With the current implementation of the double-and-add algorithm,\n' \
          'the correlation between the number of set bits in the scalar and\n' \
          'the time elapsed is approximately c = {} (over {} iterations)'.format(corr, N)
