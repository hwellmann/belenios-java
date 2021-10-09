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

export interface Signature {
    public_key: BigInteger;
    challenge: BigInteger;
    response: BigInteger;
}

export interface Ciphertext {
    alpha: BigInteger;
    beta: BigInteger;
}

export interface Proof {
    challenge: BigInteger;
    response: BigInteger;
}

export interface Answer {
    choices: Ciphertext[];
    individual_proofs: Proof[][];
    overall_proof: Proof[];
    blank_proof: Proof[];
}

export interface Ballot {
    answers: Answer[];
    election_hash: string;
    election_uuid: string;
    signature: Signature;
}

export interface Credentials {
    privateCred: string;
    publicCred: string;
}