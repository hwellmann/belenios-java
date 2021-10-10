import { BigInteger } from 'jsbn';

export interface Group {
    g: BigInteger;
    p: BigInteger;
    q: BigInteger;
}

export interface WrappedPublicKey {
    group: Group;
    y: BigInteger;
}

export interface Question {

    answers: string[];

    blank?: boolean;

    min: number;
    max: number;
    question: string
}

export interface Election {
    description: string;
    name: string;
    public_key: WrappedPublicKey;
    questions: Question[];
    uuid: string;
    administrator: string;
    credential_authority: string;
}

export function reviveElection(key: string, value: any): any {
    if (key === "g" || key === "p" || key === "q" || key === "y") {
        return new BigInteger(value);
    }
    return value;
}

export function replaceElection(key: string, value: any): any {
    if (["g", "p", "q", "y"].includes(key)) {
        return (value as BigInteger).toString();
    }
    return value;
}
export function replaceBallot(key: string, value: any): any {
    if (["g", "p", "q", "y", "challenge", "response", "alpha", "beta", "public_key" ].includes(key)) {
        return (value as BigInteger).toString();
    }
    return value;
}


export interface Signature {
    public_key: BigInteger;
    challenge: BigInteger;
    response: BigInteger;
}

export interface Ciphertext {
    alpha: BigInteger;
    beta: BigInteger;
}

export function addCt(left: Ciphertext, right: Ciphertext, p: BigInteger): Ciphertext {
    return {
        alpha: left.alpha.multiply(right.alpha).mod(p),
        beta: left.beta.multiply(right.beta).mod(p)
    }
}


export interface CiphertextAndSecret {
    alpha: BigInteger;
    beta: BigInteger;
    r: BigInteger;
}

export function addCts(left: CiphertextAndSecret, right: CiphertextAndSecret, p: BigInteger): CiphertextAndSecret {
    return {
        alpha: left.alpha.multiply(right.alpha).mod(p),
        beta: left.beta.multiply(right.beta).mod(p),
        r: left.r.add(right.r).mod(p)
    }
}

export interface Proof {
    challenge: BigInteger;
    response: BigInteger;
}

export interface Answer {
    choices: Ciphertext[];
    individual_proofs: Proof[][];
    overall_proof: Proof[];
    blank_proof?: Proof[];
}

export interface Ballot {
    answers: Answer[];
    election_hash: string;
    election_uuid: string;
    signature: Signature;
}

export interface Credentials {
    privateCred: string;
    publicCred: BigInteger;
}