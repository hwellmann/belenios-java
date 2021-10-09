import { BigInteger, SecureRandom } from 'jsbn';

export function random(q: BigInteger): BigInteger {
    const random = new SecureRandom();
    const numBits = q.bitLength();
    var r: BigInteger;
    do {
        r = new BigInteger(numBits, random);
    } while (r.compareTo(q) >= 0);
    return r;
}
