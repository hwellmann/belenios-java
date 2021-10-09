import { BigInteger } from 'jsbn';
import { Group } from './Model';
import * as sjcl from 'sjcl';

const BASE58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

const N58 = new BigInteger("58");
const N53 = new BigInteger("53");

const TOKEN_LENGTH = 14;
const RAW_CREDENTIAL_LENGTH = TOKEN_LENGTH + 1;

export function isValid(privateCred: string): boolean {
    const checksum = computeChecksum(privateCred);
    const lastChar = privateCred.charAt(privateCred.length - 1);
    return lastChar == BASE58.charAt(checksum);
}

function computeChecksum(privateCred: string): number {
    const value = toInteger(privateCred);
    const checksum = N53.subtract(value.mod(N53)).intValue();
    return checksum;
}

function toInteger(privateCred: string): BigInteger {
    const rawCred = privateCred.replace(/-/g, "");
    if (rawCred.length != RAW_CREDENTIAL_LENGTH) {
        throw new Error(privateCred);
    }

    let value = BigInteger.ZERO;
    for (let i = 0; i < RAW_CREDENTIAL_LENGTH - 1; i++) {
        const digit = rawCred.charAt(i);
        const index = BASE58.indexOf(digit);
        value = value.multiply(N58).add(new BigInteger(index.toString()));
    }
    return value;
}

export function toSecretKey(privateCred: string, uuid: string, q: BigInteger): BigInteger {
    const secret = sjcl.misc.pbkdf2(privateCred, uuid, 1000);
    const secretHex = sjcl.codec.hex.fromBits(secret);
    const secretInt = new BigInteger(secretHex, 16);
    return secretInt.mod(q);
}

export function derive(privateCred: string, uuid: string, group: Group): BigInteger {
    var secretKey = toSecretKey(privateCred, uuid, group.q);

    return group.g.modPow(secretKey, group.p);
}
