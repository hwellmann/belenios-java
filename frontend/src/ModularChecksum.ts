import { BigInteger } from "jsbn";
import * as sjcl from 'sjcl';

export function checksum(message: string, modulus: BigInteger): BigInteger {
    const hash = sjcl.hash.sha256.hash(message);
    const hex = sjcl.codec.hex.fromBits(hash);
    return new BigInteger(hex, 16).mod(modulus);
}
